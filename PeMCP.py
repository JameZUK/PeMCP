#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Comprehensive PE File Analyzer (Refactored with Integrated ssdeep and capa)

This script provides extensive analysis of Portable Executable (PE) files.
It can operate in two modes:
1. CLI Mode: Analyzes a PE file and prints a detailed report to the console.
   Supports PEiD-like signature scanning, YARA scanning, capa capability detection,
   string extraction/searching, and hex dumping.
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
import functools # Added for mcp_tool_requires_loaded_pe decorator

from pathlib import Path
# import copy # Already imported above

# Crucial: Import typing early, as it's used for global type hints and throughout the script
from typing import Dict, Any, Optional, List, Tuple, Set, Union

# --- Logging Setup (early for dependency status logging) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

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
                    sys.exit(0) # Exit so user can re-run with pefile now available
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
        except EOFError: # Handle cases like piping input from /dev/null
            print("[!] No input received for the installation prompt. Please install 'pefile' manually and re-run.", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Installation of 'pefile' cancelled by user. This library is required. Exiting.", file=sys.stderr)
            sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent

# --- VirusTotal API Configuration ---
VT_API_KEY = os.getenv("VT_API_KEY") # Your VirusTotal API Key
VT_API_URL_FILE_REPORT = "https://www.virustotal.com/api/v3/files/"

# --- Constants ---
PEID_USERDB_URL = "https://raw.githubusercontent.com/GerkNL/PEid/master/userdb.txt"
DEFAULT_PEID_DB_PATH = SCRIPT_DIR / "userdb.txt"

CAPA_RULES_ZIP_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.1.0.zip" # Using a specific tag for stability
CAPA_RULES_DEFAULT_DIR_NAME = "capa_rules_store" # Base directory for storing capa rules
CAPA_RULES_SUBDIR_NAME = "rules" # The actual subdirectory within the store that capa uses

MAX_MCP_RESPONSE_SIZE_KB = 64 # Max response size for MCP tools in KB
MAX_MCP_RESPONSE_SIZE_BYTES = MAX_MCP_RESPONSE_SIZE_KB * 1024 # Max response size in bytes

# --- Integrated SSDeep Hasher ---
class SSDeep:
    """
    Pure Python implementation of ssdeep fuzzy hashing.
    Based on the original C implementation and various Python ports.
    Handles bytes, strings, and mmap objects as input.
    """
    BLOCKSIZE_MIN = 3
    SPAMSUM_LENGTH = 64
    STREAM_BUFF_SIZE = 8192  # Process stream in chunks
    HASH_PRIME = 0x01000193
    HASH_INIT = 0x28021967
    ROLL_WINDOW = 7
    B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    class _RollState(object):
        """Internal state for the rolling hash."""
        ROLL_WINDOW = 7  # Should match SSDeep.ROLL_WINDOW

        def __init__(self):
            self.win = bytearray(self.ROLL_WINDOW)
            self.h1 = int()
            self.h2 = int()
            self.h3 = int()
            self.n = int()

        def roll_hash(self, b_val: int) -> int:
            """Update the rolling hash with a new byte."""
            self.h2 = (self.h2 - self.h1 + (self.ROLL_WINDOW * b_val)) & 0xFFFFFFFF
            self.h1 = (self.h1 + b_val - self.win[self.n % self.ROLL_WINDOW]) & 0xFFFFFFFF
            self.win[self.n % self.ROLL_WINDOW] = b_val
            self.n += 1
            self.h3 = (self.h3 << 5) & 0xFFFFFFFF
            self.h3 ^= b_val
            return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF

    def _spamsum(self, stream: io.BytesIO, slen: int) -> str:
        """
        Internal spamsum calculation logic.
        Processes the stream and generates the two parts of the ssdeep hash.
        """
        block_size = self.BLOCKSIZE_MIN
        if slen > 0: # Only adjust block_size if there's content
            while (block_size * self.SPAMSUM_LENGTH) < slen:
                if block_size >= (0xFFFFFFFF // 2): # Prevent overflow if block_size gets too large
                    break
                block_size *= 2
        
        # This loop ensures that we can reduce the block_size if the
        # resulting hash is too small.
        while True:
            stream.seek(0) # Reset stream for potential re-read with smaller block_size
            roll_state = self._RollState()
            block_hash1 = self.HASH_INIT
            block_hash2 = self.HASH_INIT
            hash_string1_list = [] # Use lists for efficient char appending
            hash_string2_list = []

            # Read the stream in chunks
            buf = stream.read(self.STREAM_BUFF_SIZE)
            while buf:
                for b_val_char in buf:
                    # b_val_char is already an int when iterating over bytes
                    block_hash1 = ((block_hash1 * self.HASH_PRIME) ^ b_val_char) & 0xFFFFFFFF
                    block_hash2 = ((block_hash2 * self.HASH_PRIME) ^ b_val_char) & 0xFFFFFFFF
                    
                    rh = roll_state.roll_hash(b_val_char)

                    if (rh % block_size) == (block_size - 1):
                        if len(hash_string1_list) < (self.SPAMSUM_LENGTH - 1):
                            hash_string1_list.append(self.B64[block_hash1 % 64])
                            block_hash1 = self.HASH_INIT
                        # Check for the second hash string only if the first isn't full
                        # and the condition for the second hash is met.
                        if (rh % (block_size * 2)) == ((block_size * 2) - 1):
                            if len(hash_string2_list) < ((self.SPAMSUM_LENGTH // 2) - 1):
                                hash_string2_list.append(self.B64[block_hash2 % 64])
                                block_hash2 = self.HASH_INIT
                buf = stream.read(self.STREAM_BUFF_SIZE)
            
            # Finalize hashes if any data was processed
            if roll_state.n > 0: # roll_state.n tracks number of bytes processed
                if len(hash_string1_list) < self.SPAMSUM_LENGTH: # Check capacity before appending
                    hash_string1_list.append(self.B64[block_hash1 % 64])
                if len(hash_string2_list) < (self.SPAMSUM_LENGTH // 2): # Check capacity
                    hash_string2_list.append(self.B64[block_hash2 % 64])

            # If the hash is too short, and we can reduce the block_size, do so and try again
            if block_size > self.BLOCKSIZE_MIN and len(hash_string1_list) < (self.SPAMSUM_LENGTH // 2):
                block_size //= 2
            else:
                break # Otherwise, we're done

        hash_string1 = "".join(hash_string1_list)
        hash_string2 = "".join(hash_string2_list)
        return f'{block_size}:{hash_string1}:{hash_string2}'

    def hash(self, buf_data_input: Union[bytes, str, mmap.mmap]) -> str:
        """
        Computes the ssdeep fuzzy hash for the given input data.

        Args:
            buf_data_input: Data to hash. Can be bytes, a string (UTF-8 encoded),
                            or an mmap object.

        Returns:
            The ssdeep hash string.

        Raises:
            TypeError: If the input data is not bytes, string, or mmap.mmap.
        """
        buf_data_bytes: bytes
        if isinstance(buf_data_input, bytes):
            buf_data_bytes = buf_data_input
        elif isinstance(buf_data_input, str):
            buf_data_bytes = buf_data_input.encode('utf-8', 'ignore')
        elif isinstance(buf_data_input, mmap.mmap):
            # Read the entire mmap object into bytes.
            # This is necessary because mmap objects might be modified,
            # and we need a stable byte sequence for hashing.
            # Also, io.BytesIO expects bytes.
            buf_data_bytes = buf_data_input[:]
        else:
            raise TypeError(f"Argument must be of bytes, string, or mmap.mmap type, not {type(buf_data_input)}")

        if not buf_data_bytes: # Handle empty input
            # For empty input, ssdeep typically returns "blocksize::"
            return f"{self.BLOCKSIZE_MIN}::"

        return self._spamsum(io.BytesIO(buf_data_bytes), len(buf_data_bytes))

    def _levenshtein(self, s: str, t: str) -> int:
        """Computes the Levenshtein distance between two strings."""
        if s == t: return 0
        if not s: return len(t)
        if not t: return len(s)

        v0 = list(range(len(t) + 1))
        v1 = [0] * (len(t) + 1)

        for i in range(len(s)):
            v1[0] = i + 1
            for j in range(len(t)):
                cost = 0 if s[i] == t[j] else 1
                v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
            v0, v1 = v1, v0 # Swap lists
        return v0[len(t)]

    def _common_substring(self, s1: str, s2: str) -> bool:
        """
        Checks if two strings share a common substring of at least ROLL_WINDOW length
        using rolling hashes.
        """
        if not s1 or not s2 or min(len(s1), len(s2)) < self.ROLL_WINDOW:
            return False

        hashes_s1 = []
        roll_s1 = self._RollState()
        for char_val in s1.encode('utf-8', 'ignore'): # Iterate over bytes
            hashes_s1.append(roll_s1.roll_hash(char_val))

        roll_s2 = self._RollState()
        for i, char_val_s2 in enumerate(s2.encode('utf-8', 'ignore')):
            rh_s2 = roll_s2.roll_hash(char_val_s2)
            if i < (self.ROLL_WINDOW - 1):
                continue

            # Compare with hashes from s1
            # Adjust index for s1_hashes to match current window in s2
            for j in range(self.ROLL_WINDOW - 1, len(hashes_s1)):
                if hashes_s1[j] == rh_s2:
                    # Potential match, verify actual substring
                    # s2_idx is the start of the current window in s2
                    # s1_idx is the start of the corresponding window in s1
                    s2_idx = i - (self.ROLL_WINDOW - 1)
                    s1_idx = j - (self.ROLL_WINDOW - 1)
                    
                    # Ensure slices are valid
                    if (s2_idx + self.ROLL_WINDOW <= len(s2) and
                        s1_idx + self.ROLL_WINDOW <= len(s1)):
                        # Compare actual byte sequences for confirmation
                        if s2.encode('utf-8','ignore')[s2_idx : s2_idx + self.ROLL_WINDOW] == \
                           s1.encode('utf-8','ignore')[s1_idx : s1_idx + self.ROLL_WINDOW]:
                            return True
        return False

    def _score_strings(self, s1: str, s2: str, block_size: int) -> int:
        """Scores similarity between two hash strings (parts of ssdeep)."""
        if not self._common_substring(s1, s2):
            return 0
        
        # Handle empty strings explicitly after common_substring check
        if not s1 and not s2: return 100 # Both empty, perfect match in context
        if not s1 or not s2: return 0   # One empty, no match

        lev_score = self._levenshtein(s1, s2)
        sum_len = len(s1) + len(s2)
        
        # This check should ideally not be needed if common_substring handles empty s1/s2,
        # but as a safeguard:
        if sum_len == 0: return 100 

        # Original ssdeep scoring logic
        score = (lev_score * self.SPAMSUM_LENGTH) // sum_len
        score = (100 * score) // self.SPAMSUM_LENGTH
        score = 100 - score

        # Clamp score based on block_size and minimum length
        min_len_s1_s2 = min(len(s1), len(s2))
        # cap_val calculation should prevent division by zero if BLOCKSIZE_MIN is > 0
        cap_val = (block_size // self.BLOCKSIZE_MIN) * min_len_s1_s2 if self.BLOCKSIZE_MIN > 0 else min_len_s1_s2
        
        if score > cap_val:
            score = cap_val
        
        return score

    def _strip_sequences(self, s: str) -> str:
        """Strips sequences of identical characters longer than 3."""
        if len(s) <= 3: return s
        
        res_list = list(s[:3]) # Start with the first 3 characters
        for i in range(3, len(s)):
            # Append if current char is different from any of the preceding 3
            if (s[i] != s[i-1] or 
                s[i] != s[i-2] or 
                s[i] != s[i-3]):
                res_list.append(s[i])
        return "".join(res_list)

    def compare(self, hash1_str: str, hash2_str: str) -> int:
        """
        Compares two ssdeep hashes and returns a similarity score (0-100).

        Args:
            hash1_str: The first ssdeep hash string.
            hash2_str: The second ssdeep hash string.

        Returns:
            An integer score from 0 (no similarity) to 100 (identical).

        Raises:
            TypeError: If arguments are not strings.
            ValueError: If hashes are malformed.
        """
        if not (isinstance(hash1_str, str) and isinstance(hash2_str, str)):
            raise TypeError('Arguments must be of string type')
        
        try:
            hash1_parts = hash1_str.split(':', 2)
            hash2_parts = hash2_str.split(':', 2)
            if len(hash1_parts) != 3 or len(hash2_parts) != 3:
                # Check for "blocksize::" format for empty files
                if (len(hash1_parts) == 3 and hash1_parts[1] == "" and hash1_parts[2] == "" and
                    len(hash2_parts) == 3 and hash2_parts[1] == "" and hash2_parts[2] == ""):
                    # Both are empty hashes, compare block sizes
                    return 100 if hash1_parts[0] == hash2_parts[0] else 0
                raise ValueError('Invalid hash format (must have 3 parts: blocksize:string1:string2)')

            hash1_bs_str, hash1_s1, hash1_s2 = hash1_parts
            hash2_bs_str, hash2_s1, hash2_s2 = hash2_parts

            hash1_bs = int(hash1_bs_str)
            hash2_bs = int(hash2_bs_str)
        except ValueError as e: # Catches int conversion errors or the custom ValueError
            raise ValueError(f'Invalid hash format: {e}') from None # Suppress original exception context

        # Block size compatibility check
        if not (hash1_bs == hash2_bs or \
                hash1_bs == (hash2_bs * 2) or \
                hash2_bs == (hash1_bs * 2)):
            return 0

        # Handle cases where one or both hashes are for empty files ("blocksize::")
        is_hash1_empty_payload = (hash1_s1 == "" and hash1_s2 == "")
        is_hash2_empty_payload = (hash2_s1 == "" and hash2_s2 == "")

        if is_hash1_empty_payload and is_hash2_empty_payload:
            return 100 # Both represent empty files, considered identical if block sizes are compatible
        if is_hash1_empty_payload or is_hash2_empty_payload:
            return 0 # One is empty, the other is not; no similarity

        # Strip sequences from non-empty hash parts
        hash1_s1 = self._strip_sequences(hash1_s1)
        hash1_s2 = self._strip_sequences(hash1_s2)
        hash2_s1 = self._strip_sequences(hash2_s1)
        hash2_s2 = self._strip_sequences(hash2_s2)

        # Main comparison logic based on block sizes
        score = 0
        if hash1_bs == hash2_bs:
            # If block sizes are the same, compare both parts and take the max score
            # Also, if s1 parts are identical, it's a 100% match (common optimization)
            if hash1_s1 == hash2_s1: return 100
            score1 = self._score_strings(hash1_s1, hash2_s1, hash1_bs)
            score2 = self._score_strings(hash1_s2, hash2_s2, hash1_bs) # Note: original uses hash1_bs here too
            score = max(score1, score2)
        elif hash1_bs == (hash2_bs * 2):
            # Compare s1 of hash1 with s2 of hash2
            score = self._score_strings(hash1_s1, hash2_s2, hash1_bs)
        else: # hash2_bs == (hash1_bs * 2)
            # Compare s2 of hash1 with s1 of hash2
            score = self._score_strings(hash2_s1, hash1_s2, hash2_bs) # Note: original uses hash2_bs

        return int(score) # Ensure integer result

# Global instance of the hasher
ssdeep_hasher = SSDeep()


# --- Optional Dependencies Configuration ---
# spec_name: The module name used for importlib.util.find_spec or direct import.
# pip_name: The name used for `pip install`.
# friendly_name: User-friendly name for messages.
# is_critical_for_mcp_mode: True if MCP server mode *requires* this.
# is_critical_for_cli_mode: True if CLI mode *requires* this (beyond pefile). (Currently none)
DEPENDENCIES = [
    {"spec_name": "cryptography", "pip_name": "cryptography", "friendly_name": "Cryptography (for digital signatures)", "is_critical_mcp": False, "is_critical_cli": False},
    {"spec_name": "requests", "pip_name": "requests", "friendly_name": "Requests (for PEiD DB/capa rules download, VT)", "is_critical_mcp": False, "is_critical_cli": False},
    {"spec_name": "signify.authenticode", "pip_name": "signify", "friendly_name": "Signify (for Authenticode validation)", "is_critical_mcp": False, "is_critical_cli": False},
    {"spec_name": "yara", "pip_name": "yara-python", "friendly_name": "Yara (for YARA scanning)", "is_critical_mcp": False, "is_critical_cli": False},
    {"spec_name": "capa.main", "pip_name": "flare-capa", "friendly_name": "Capa (for capability detection)", "is_critical_mcp": False, "is_critical_cli": False},
    {"spec_name": "mcp.server.fastmcp", "pip_name": "mcp[cli]", "friendly_name": "MCP SDK (for MCP server mode)", "is_critical_mcp": True, "is_critical_cli": False}
]

# --- Global Availability Flags & Import Errors Store ---
# These will be set by _initialize_and_log_dependency_statuses()
CRYPTOGRAPHY_AVAILABLE = False
REQUESTS_AVAILABLE = False
SIGNIFY_AVAILABLE = False
YARA_AVAILABLE = False
CAPA_AVAILABLE = False # This will be set based on a more complex capa import attempt
MCP_SDK_AVAILABLE = False

OPTIONAL_DEPENDENCY_IMPORT_ERRORS: Dict[str, str] = {} # Stores pip_name -> error_string

def _initialize_and_log_dependency_statuses():
    """
    Checks availability of optional dependencies, sets global flags,
    and logs their status. This should be called once at script startup.
    """
    global CRYPTOGRAPHY_AVAILABLE, REQUESTS_AVAILABLE, SIGNIFY_AVAILABLE, \
           YARA_AVAILABLE, CAPA_AVAILABLE, MCP_SDK_AVAILABLE, \
           OPTIONAL_DEPENDENCY_IMPORT_ERRORS

    logger.info("Initializing and checking status of optional dependencies...")

    for dep_info in DEPENDENCIES:
        spec_name = dep_info["spec_name"]
        pip_name = dep_info["pip_name"]
        friendly_name = dep_info["friendly_name"]
        available = False
        import_error_message = "Not found or import failed."

        try:
            if spec_name == "capa.main": # Special handling for capa
                # Attempting the more complex capa import sequence
                # This is a simplified version for status checking; actual capa usage is more involved.
                import capa
                import capa.main # Attempt to import a key module
                # If the above succeed, we consider capa "basically available".
                # Finer-grained checks happen during capa analysis itself.
                CAPA_AVAILABLE = True
                available = True
                logger.info(f"Optional library '{friendly_name}' (capa) appears to be available.")
            elif spec_name == "mcp.server.fastmcp": # Special handling for MCP SDK
                import mcp.server.fastmcp # Attempt to import FastMCP
                MCP_SDK_AVAILABLE = True
                available = True
                logger.info(f"Optional library '{friendly_name}' (MCP SDK) is available.")
            else: # Standard import check for other libraries
                module_spec = importlib.util.find_spec(spec_name)
                if module_spec:
                    # For an extra check, actually try importing it
                    importlib.import_module(spec_name)
                    available = True
                    logger.info(f"Optional library '{friendly_name}' ({spec_name}) is available.")
                else:
                    import_error_message = f"Module spec '{spec_name}' not found."
                    logger.warning(f"Optional library '{friendly_name}' ({spec_name}) not found.")

            # Update global flags based on availability
            if spec_name == "cryptography": CRYPTOGRAPHY_AVAILABLE = available
            elif spec_name == "requests": REQUESTS_AVAILABLE = available
            elif spec_name == "signify.authenticode": SIGNIFY_AVAILABLE = available
            elif spec_name == "yara": YARA_AVAILABLE = available
            # CAPA_AVAILABLE and MCP_SDK_AVAILABLE are set directly in their special blocks

        except ImportError as e_imp:
            import_error_message = f"ImportError: {e_imp}"
            logger.warning(f"Optional library '{friendly_name}' ({spec_name}) import failed: {e_imp}")
            OPTIONAL_DEPENDENCY_IMPORT_ERRORS[pip_name] = str(e_imp)
        except Exception as e_gen: # Catch any other unexpected errors during import
            import_error_message = f"Unexpected error during import check: {e_gen}"
            logger.error(f"Unexpected error checking '{friendly_name}' ({spec_name}): {e_gen}", exc_info=logger.level == logging.DEBUG)
            OPTIONAL_DEPENDENCY_IMPORT_ERRORS[pip_name] = str(e_gen)
        
        if not available and pip_name not in OPTIONAL_DEPENDENCY_IMPORT_ERRORS:
            # If it failed silently (e.g. find_spec returned None but no ImportError)
             OPTIONAL_DEPENDENCY_IMPORT_ERRORS[pip_name] = import_error_message


def check_and_install_dependencies(is_mcp_server_mode_arg: bool):
    """
    Checks for missing optional dependencies based on pre-set global availability flags
    and prompts the user to install them if running interactively.
    Exits if critical dependencies for the current mode are missing and not installed.
    """
    missing_deps_info = []
    critical_missing_for_current_mode = False

    # Use the global availability flags determined by _initialize_and_log_dependency_statuses()
    dep_availability_map = {
        "cryptography": CRYPTOGRAPHY_AVAILABLE,
        "requests": REQUESTS_AVAILABLE,
        "signify.authenticode": SIGNIFY_AVAILABLE, # Note: spec_name used here
        "yara": YARA_AVAILABLE,
        "capa.main": CAPA_AVAILABLE,               # Note: spec_name used here
        "mcp.server.fastmcp": MCP_SDK_AVAILABLE    # Note: spec_name used here
    }

    for dep_config in DEPENDENCIES:
        spec_name = dep_config["spec_name"]
        pip_name = dep_config["pip_name"]
        friendly_name = dep_config["friendly_name"]
        is_critical_mcp = dep_config["is_critical_mcp"]
        # is_critical_cli = dep_config["is_critical_cli"] # Not currently used but available

        is_available = dep_availability_map.get(spec_name, False)

        if not is_available:
            import_error_msg = OPTIONAL_DEPENDENCY_IMPORT_ERRORS.get(pip_name, "Not found or import failed.")
            missing_deps_info.append({
                "pip": pip_name,
                "friendly": friendly_name,
                "is_critical_mcp": is_critical_mcp,
                "error_details": import_error_msg
            })
            if is_critical_mcp and is_mcp_server_mode_arg:
                critical_missing_for_current_mode = True
            # Add similar logic for is_critical_cli if needed in the future

    if not missing_deps_info:
        logger.info("All checked optional dependencies are available or their status is known.")
        return

    print("\n[!] Some optional libraries are missing or could not be imported:", file=sys.stderr)
    for dep in missing_deps_info:
        error_detail_str = f" (Error: {dep['error_details']})" if dep['error_details'] and dep['error_details'] != "Not found or import failed." else ""
        print(f"     - {dep['friendly']} (Python package: {dep['pip']}){error_detail_str}", file=sys.stderr)

    if critical_missing_for_current_mode:
        print("[!] One or more libraries critical for --mcp-server mode are missing.", file=sys.stderr)
    # Add similar message for CLI critical if that concept is used

    print("[!] These libraries enhance the script's functionality or are required for specific modes.", file=sys.stderr)

    try:
        if not sys.stdin.isatty(): # Non-interactive environment
            print("[!] Non-interactive environment detected. Cannot prompt for installation of optional libraries.", file=sys.stderr)
            if critical_missing_for_current_mode:
                print("[!] Please install the required MCP SDK ('pip install \"mcp[cli]\"') and/or other critical optional libraries manually and re-run.", file=sys.stderr)
                sys.exit(1) # Critical missing in non-interactive is fatal
            print("[!] Please install other missing optional libraries manually if needed.", file=sys.stderr)
            return

        # Interactive environment, prompt for installation
        answer = input("Do you want to attempt to install the missing optional libraries now? (yes/no): ").strip().lower()
        if answer == 'yes' or answer == 'y':
            installed_any_successfully = False
            critical_still_missing_after_install = critical_missing_for_current_mode # Assume still missing until installed

            for dep_to_install in missing_deps_info:
                # Only try to install if it's actually part of the missing list
                print(f"[*] Attempting to install {dep_to_install['friendly']} (pip install \"{dep_to_install['pip']}\")...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep_to_install['pip']])
                    print(f"[*] Successfully installed {dep_to_install['friendly']}.")
                    installed_any_successfully = True
                    # If a critical dep was installed, update flag
                    if dep_to_install['is_critical_mcp'] and is_mcp_server_mode_arg:
                        # This is tricky because we can't re-check import easily here without restarting.
                        # The user is told to restart. So, we assume it might be fixed on restart.
                        # For immediate exit logic, we'd have to be more pessimistic or try a dynamic import.
                        # For now, the script exits and asks for re-run if any were installed.
                        pass # Handled by the exit below
                except subprocess.CalledProcessError as e_pip_install:
                    print(f"[!] Error installing {dep_to_install['friendly']}: {e_pip_install}", file=sys.stderr)
                except FileNotFoundError: # Pip itself not found
                    print("[!] Error: 'pip' command or Python executable not found. Is Python and pip installed correctly and in PATH?", file=sys.stderr)
                    print("[!] Cannot install missing libraries automatically.", file=sys.stderr)
                    break # Stop trying if pip is missing

            if installed_any_successfully:
                print("\n[*] Optional library installation process finished.")
                print("[*] IMPORTANT: Please re-run the script for the changes to take full effect and for the new libraries to be recognized.")
                sys.exit(0) # Exit to force re-run
            else:
                print("[*] No optional libraries were successfully installed (or none were attempted).")
                if critical_missing_for_current_mode: # If critical ones were targeted but failed
                    print("[!] Critical dependencies were not installed. The script may not function as expected in the current mode. Exiting.", file=sys.stderr)
                    sys.exit(1)
        else: # User chose not to install
            print("[*] Skipping installation of optional libraries.")
            if critical_missing_for_current_mode:
                print("[!] Critical dependencies were not installed because installation was skipped. The script cannot function correctly in the current mode. Exiting.", file=sys.stderr)
                sys.exit(1)
    except EOFError:
        print("[!] No input received for optional library installation prompt. Skipping.", file=sys.stderr)
        if critical_missing_for_current_mode:
            print("[!] Critical dependencies were not installed. Exiting.", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Optional library installation cancelled by user.", file=sys.stderr)
        if critical_missing_for_current_mode:
            print("[!] Critical dependencies were not installed. Exiting.", file=sys.stderr)
            sys.exit(1)

# --- Capa Specific Exception Classes (defined before capa import attempts) ---
class CapaError(Exception):
    """Base class for capa related errors in this script."""
    def __init__(self, msg="Generic Capa Error", status_code=None):
        super().__init__(msg)
        self.status_code = status_code

class InvalidRule(CapaError): pass
class RulesAccessError(CapaError): pass # For issues like download/extraction
class FreezingError(CapaError): pass # If capa's freezing mechanism has issues

# --- Attempt to import Capa and its components ---
# This block sets CAPA_AVAILABLE and potentially CAPA_IMPORT_ERROR
CAPA_IMPORT_ERROR: Optional[str] = None
try:
    import capa
    import capa.main
    import capa.rules
    import capa.loader
    import capa.capabilities.common
    import capa.render.result_document as rd
    import capa.engine
    import capa.render.json as capa_json_render # For potential direct JSON rendering
    import capa.features.extractors.pefile as capa_pefile_extractor
    import capa.features.common # For FORMAT_PE, OS_WINDOWS etc.

    # Import specific capa exceptions if available (modern capa versions)
    from capa.exceptions import (
        InvalidArgument,
        EmptyReportError,
        UnsupportedOSError,
        UnsupportedArchError,
        UnsupportedFormatError,
        UnsupportedRuntimeError,
        # ShouldExitError, # This one is often handled by capa.main internally
    )
    CAPA_AVAILABLE = True # Set flag if all critical imports succeed
    logger.info("Successfully imported capa modules and exceptions. PeMCP.py will attempt to use this capa API.")

except ImportError as e:
    CAPA_IMPORT_ERROR = f"Failed to import one or more capa modules: {str(e)}"
    CAPA_AVAILABLE = False # Ensure it's False on any import failure
    # This warning will be logged by _initialize_and_log_dependency_statuses if capa is in DEPENDENCIES
    # logger.warning(f"{CAPA_IMPORT_ERROR}. Capa analysis will be skipped or limited.")
except Exception as e_generic_capa: # Catch any other unexpected error during capa import
    CAPA_IMPORT_ERROR = f"An unexpected error occurred during capa import attempts: {str(e_generic_capa)}"
    CAPA_AVAILABLE = False
    # logger.error(CAPA_IMPORT_ERROR, exc_info=logger.level == logging.DEBUG)

# --- MCP SDK Import Attempt ---
# This sets MCP_SDK_AVAILABLE and is logged by _initialize_and_log_dependency_statuses
# The mock objects are fallbacks if the SDK isn't present.
try:
    from mcp.server.fastmcp import FastMCP, Context
    MCP_SDK_AVAILABLE = True # Set by _initialize_and_log_dependency_statuses based on this
except ImportError:
    # MCP_SDK_AVAILABLE remains False (its default)
    # Mock objects for graceful non-MCP execution or if user tries to run MCP mode without the SDK
    class MockSettings:
        host = "127.0.0.1"
        port = 8081 # Default, might be overridden by args
        log_level = "INFO"

    class MockMCP:
        def __init__(self, name, description=""):
            self.name = name
            self.description = description
            self.app = object() # Mock app object
            self.settings = MockSettings()
            self._run_called_with_transport = None # For potential testing/debugging
            # logger.warning(f"MockMCP initialized for '{name}'. MCP SDK not found.")

        def tool(self):
            # This decorator should still allow the function to be defined
            # but it won't be registered with a real MCP server.
            decorator = lambda func: func
            return decorator

        def run(self, transport: str = "stdio"):
            # Log that the mock run was called, but don't actually start a server
            self._run_called_with_transport = transport
            # Use print for direct user feedback if this mock is somehow run
            print(f"[MockMCP] '{self.name}' run method called with transport='{transport}'.")
            print("[MockMCP] MCP SDK is not installed, so no server is actually started.")
            print("[MockMCP] Please install 'mcp[cli]' to use MCP server functionality.")
    
    FastMCP = MockMCP # type: ignore # Assign mock to the name expected by the script
    
    class Context: # type: ignore
        """Mock MCP Context for when the SDK is not available."""
        async def info(self, msg: str): print(f"(Mock MCP Context INFO): {msg}")
        async def error(self, msg: str): print(f"(Mock MCP Context ERROR): {msg}", file=sys.stderr)
        async def warning(self, msg: str): print(f"(Mock MCP Context WARNING): {msg}", file=sys.stderr)
        # Add other methods if your tools use them and you want to mock them

# --- Global State for MCP ---
ANALYZED_PE_FILE_PATH: Optional[str] = None
ANALYZED_PE_DATA: Optional[Dict[str, Any]] = None
PEFILE_VERSION_USED: Optional[str] = None # To store pefile.__version__
PE_OBJECT_FOR_MCP: Optional[pefile.PE] = None # This will hold the single pre-loaded PE object for MCP mode

# --- Utility Functions ---
def safe_print(text_to_print: Any, verbose_prefix: str = ""):
    """
    Prints text safely, attempting to handle UnicodeEncodeErrors by replacing or escaping characters.
    Args:
        text_to_print: The text/object to print (will be converted to str).
        verbose_prefix: A prefix string, often used for verbose logging indentation.
    """
    try:
        print(f"{verbose_prefix}{str(text_to_print)}")
    except UnicodeEncodeError:
        try:
            # Fallback for encoding errors: try to encode with backslashreplace, then decode.
            # This is a common strategy to make unencodable characters visible.
            output_encoding = sys.stdout.encoding if sys.stdout.encoding else 'utf-8' # Default to utf-8
            encoded_text = str(text_to_print).encode(output_encoding, errors='backslashreplace').decode(output_encoding, errors='ignore')
            print(f"{verbose_prefix}{encoded_text} (some characters replaced/escaped due to encoding issues)")
        except Exception: # Broad exception if even the fallback fails
            # Last resort if everything else fails
            print(f"{verbose_prefix}<Unencodable string: contains characters not supported by the current output encoding>")
    except Exception as e_print: # Catch other potential print errors
        # This could happen for very unusual objects if str() fails, though rare.
        print(f"{verbose_prefix}<Error during printing: {type(e_print).__name__} - {str(e_print)[:100]}>")


def format_timestamp(timestamp_val: int) -> str:
    """
    Formats a Unix timestamp into a human-readable UTC string.
    Includes checks for common invalid or unusual timestamp values.

    Args:
        timestamp_val: The Unix timestamp (integer).

    Returns:
        A string representing the formatted date, or an error/note string if invalid.
    """
    if not isinstance(timestamp_val, int) or timestamp_val < 0:
        return f"{timestamp_val} (Invalid timestamp: must be a non-negative integer)"
    if timestamp_val == 0:
        return "0 (Timestamp is zero, often means not set or invalid)"

    current_year = datetime.datetime.now(datetime.timezone.utc).year
    try:
        dt_obj = datetime.datetime.fromtimestamp(timestamp_val, datetime.timezone.utc)
        formatted_date = dt_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        # Check for suspiciously old or far-future dates
        if dt_obj.year > current_year + 30 or dt_obj.year < 1970: # Adjusted lower bound slightly
            return f"{formatted_date} (Timestamp value: {timestamp_val}) (Note: Year is unusual)"
        return formatted_date
    except (ValueError, OSError, OverflowError) as e_ts: # Catch errors fromtimestamp might raise
        return f"{timestamp_val} (Invalid or out-of-range timestamp value: {e_ts})"


def get_file_characteristics(flags: int) -> List[str]:
    """Returns a list of human-readable file characteristics from PE header flags."""
    characteristics = []
    # Iterate over known characteristics in pefile.IMAGE_CHARACTERISTICS
    for flag_name, flag_val in pefile.IMAGE_CHARACTERISTICS.items():
        # Ensure flag_val is an int before bitwise AND, as some entries might not be.
        if isinstance(flag_val, int) and (flags & flag_val):
            characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE_SET"] # Return explicit "NONE_SET" if empty


def get_dll_characteristics(flags: int) -> List[str]:
    """Returns a list of human-readable DLL characteristics from PE header flags."""
    characteristics = []
    for flag_name, flag_val in pefile.DLL_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val):
            characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE_SET"]


def get_section_characteristics(flags: int) -> List[str]:
    """Returns a list of human-readable section characteristics from PE section header flags."""
    characteristics = []
    for flag_name, flag_val in pefile.SECTION_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val):
            characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE_SET"]


def get_relocation_type_str(reloc_type: int) -> str:
    """Converts a relocation type integer to its string representation."""
    # Create a reverse mapping from value to name for pefile.RELOCATION_TYPE
    reloc_types_map = {val: name for name, val in pefile.RELOCATION_TYPE.items() if isinstance(val, int)}
    return reloc_types_map.get(reloc_type, f"UNKNOWN_RELOC_TYPE_{reloc_type}")


def get_symbol_type_str(sym_type: int) -> str:
    """Converts a COFF symbol type integer to its string representation."""
    # Based on Microsoft COFF specification and pefile's interpretation
    base_types = {
        0x0: "NULL", 0x1: "VOID", 0x2: "CHAR", 0x3: "SHORT", 0x4: "INT",
        0x5: "LONG", 0x6: "FLOAT", 0x7: "DOUBLE", 0x8: "STRUCT", 0x9: "UNION",
        0xA: "ENUM", 0xB: "MOE (Member of Enum)", 0xC: "BYTE", 0xD: "WORD",
        0xE: "UINT", 0xF: "DWORD"
    }
    # Derived types (shifted by 4 bits)
    # IMAGE_SYM_DTYPE_POINTER, IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_DTYPE_ARRAY
    # These are usually 1, 2, 3 respectively after shifting.
    # pefile might have these constants directly, e.g., pefile.IMAGE_SYM_DTYPE_POINTER
    
    base_type_val = sym_type & 0x000F
    derived_type_val = (sym_type & 0x00F0) >> 4 # More commonly 0x0F0, but pefile uses 0x00F0 for Type field

    type_str = base_types.get(base_type_val, f"UNKNOWN_BASE_TYPE({hex(base_type_val)})")

    # Check for pefile constants first for derived types
    dtype_pointer = getattr(pefile, 'IMAGE_SYM_DTYPE_POINTER', 1) # Default to common value if not found
    dtype_function = getattr(pefile, 'IMAGE_SYM_DTYPE_FUNCTION', 2)
    dtype_array = getattr(pefile, 'IMAGE_SYM_DTYPE_ARRAY', 3)

    if derived_type_val == dtype_pointer:
        type_str = f"POINTER_TO_{type_str}"
    elif derived_type_val == dtype_function:
        type_str = f"FUNCTION_RETURNING_{type_str}"
    elif derived_type_val == dtype_array:
        type_str = f"ARRAY_OF_{type_str}"
    elif derived_type_val != 0: # If there's a derived type not matching known ones
        type_str = f"DERIVED({hex(derived_type_val)})_OF_{type_str}"


    # Special case for IMAGE_SYM_TYPE_FUNCTION (value 0x20 or 32)
    # This is a specific type, not just a derived type.
    # Check if pefile has IMAGE_SYM_TYPE_FUNCTION, otherwise use common value 0x20.
    sym_type_function_val = getattr(pefile, 'IMAGE_SYM_TYPE_FUNCTION', 0x20)
    if sym_type == sym_type_function_val:
        return "FUNCTION (IMAGE_SYM_TYPE_FUNCTION)"
        
    return type_str


def get_symbol_storage_class_str(storage_class: int) -> str:
    """Converts a COFF symbol storage class integer to its string representation."""
    # Start with a base map of common values
    classes = {
        0: "NULL", 1: "AUTOMATIC", 2: "EXTERNAL", 3: "STATIC", 4: "REGISTER",
        5: "EXTERNAL_DEF", 6: "LABEL", 7: "UNDEFINED_LABEL", 8: "MEMBER_OF_STRUCT",
        9: "ARGUMENT", 10: "STRUCT_TAG", 11: "MEMBER_OF_UNION", 12: "UNION_TAG",
        13: "TYPE_DEFINITION", 14: "UNDEFINED_STATIC", 15: "ENUM_TAG",
        16: "MEMBER_OF_ENUM", 17: "REGISTER_PARAM", 18: "BIT_FIELD",
        # Common values for IMAGE_SYM_CLASS constants (often > 18)
        100: "BLOCK", 101: "FUNCTION (End of Function or Begin of Function, context dependent)",
        102: "END_OF_STRUCT", 103: "FILE (Filename)", 104: "SECTION",
        105: "WEAK_EXTERNAL", 107: "CLR_TOKEN"
    }
    # Dynamically add mappings from pefile.SYMBOL_STORAGE_CLASSES if available
    if hasattr(pefile, 'SYMBOL_STORAGE_CLASSES'):
        # pefile.SYMBOL_STORAGE_CLASSES is usually like {'IMAGE_SYM_CLASS_STATIC': 3, ...}
        pefile_classes = {
            val: name.replace("IMAGE_SYM_CLASS_", "") # Get cleaner names
            for name, val in pefile.SYMBOL_STORAGE_CLASSES.items() if isinstance(val, int)
        }
        classes.update(pefile_classes) # Update our map, pefile's names take precedence if keys overlap

    return classes.get(storage_class, f"UNKNOWN_STORAGE_CLASS({storage_class})")


def _dump_aux_symbol_to_dict(parent_symbol_struct, aux_symbol_struct, aux_idx: int) -> Dict[str, Any]:
    """
    Dumps an auxiliary COFF symbol record to a dictionary, interpreting its format
    based on the parent symbol's storage class and type.

    Args:
        parent_symbol_struct: The structure of the parent COFF symbol.
        aux_symbol_struct: The structure of the auxiliary symbol record.
                           This can be a pefile structure object or raw bytes.
        aux_idx: The index of this auxiliary record (0-based relative to parent).

    Returns:
        A dictionary representing the parsed auxiliary symbol.
    """
    aux_dict: Dict[str, Any] = {"aux_record_index": aux_idx + 1, "interpretation_status": "Interpreted"}
    parent_storage_class = getattr(parent_symbol_struct, 'StorageClass', -1)
    parent_type = getattr(parent_symbol_struct, 'Type', -1) # For function checks

    # Get pefile constants safely, with fallbacks to common values
    sym_class_file = getattr(pefile, 'IMAGE_SYM_CLASS_FILE', 103)
    sym_class_section = getattr(pefile, 'IMAGE_SYM_CLASS_SECTION', 104)
    sym_class_static = getattr(pefile, 'IMAGE_SYM_CLASS_STATIC', 3)
    sym_class_function = getattr(pefile, 'IMAGE_SYM_CLASS_FUNCTION', 101) # For .bf, .ef symbols
    sym_class_weak_external = getattr(pefile, 'IMAGE_SYM_CLASS_WEAK_EXTERNAL', 105)
    
    # For checking if parent is a function definition (e.g., Type >> 4 == IMAGE_SYM_DTYPE_FUNCTION)
    dtype_function_val = getattr(pefile, 'IMAGE_SYM_DTYPE_FUNCTION', 2) # Common value for derived type: function

    # Format 1: Filename (if parent StorageClass is IMAGE_SYM_CLASS_FILE)
    if parent_storage_class == sym_class_file:
        aux_dict["type"] = "Filename Auxiliary Record"
        # The 'Name' attribute in aux_symbol_struct for IMAGE_SYM_CLASS_FILE
        # might be raw bytes representing the filename.
        name_bytes = getattr(aux_symbol_struct, 'Name', b'')
        if not name_bytes and hasattr(aux_symbol_struct, 'strings'): # Fallback for some pefile versions/structs
            name_bytes = aux_symbol_struct.strings
        
        name_str = "N/A"
        if isinstance(name_bytes, bytes):
            try:
                name_str = name_bytes.decode('utf-8', 'ignore').rstrip('\x00')
            except UnicodeDecodeError:
                name_str = name_bytes.decode('latin-1', 'ignore').rstrip('\x00') # Try another common encoding
            except Exception: # Broad catch if decoding fails badly
                name_str = name_bytes.hex() # Show as hex if unreadable
        elif isinstance(name_bytes, str): # If it's already a string
            name_str = name_bytes.rstrip('\x00')
        aux_dict["filename"] = name_str
        return aux_dict

    # Format 2: Section Definition (if parent StorageClass is IMAGE_SYM_CLASS_SECTION,
    # or IMAGE_SYM_CLASS_STATIC and SectionNumber > 0 for .sdata, .bss etc.)
    is_section_def_context = (parent_storage_class == sym_class_section or
                              (parent_storage_class == sym_class_static and
                               getattr(parent_symbol_struct, 'SectionNumber', 0) > 0))
    if is_section_def_context:
        aux_dict["type"] = "Section Definition Auxiliary Record"
        if hasattr(aux_symbol_struct, 'Length'): aux_dict["length"] = aux_symbol_struct.Length
        if hasattr(aux_symbol_struct, 'NumberOfRelocations'): aux_dict["number_of_relocations"] = aux_symbol_struct.NumberOfRelocations
        if hasattr(aux_symbol_struct, 'NumberOfLinenumbers'): aux_dict["number_of_linenumbers"] = aux_symbol_struct.NumberOfLinenumbers
        if hasattr(aux_symbol_struct, 'CheckSum'): aux_dict["checksum"] = hex(aux_symbol_struct.CheckSum)
        # COMDAT related fields (Number, Selection)
        if hasattr(aux_symbol_struct, 'Number'): aux_dict["number_comdat_section_assoc"] = aux_symbol_struct.Number # Section number this COMDAT refers to
        if hasattr(aux_symbol_struct, 'Selection'):
            comdat_selection_map = {
                0: "NODUPLICATES (Error if multiple definitions)", # IMAGE_COMDAT_SELECT_NODUPLICATES
                1: "ANY (Pick any definition)",                  # IMAGE_COMDAT_SELECT_ANY
                2: "SAME_SIZE (Pick any, must be same size)",    # IMAGE_COMDAT_SELECT_SAME_SIZE
                3: "EXACT_MATCH (Pick any, must be exact match)",# IMAGE_COMDAT_SELECT_EXACT_MATCH
                4: "ASSOCIATIVE (Link with another section)",    # IMAGE_COMDAT_SELECT_ASSOCIATIVE
                5: "LARGEST (Pick largest definition)",          # IMAGE_COMDAT_SELECT_LARGEST
                6: "NEWEST"                                      # IMAGE_COMDAT_SELECT_NEWEST (less common)
            }
            sel_val = aux_symbol_struct.Selection
            aux_dict["selection_comdat"] = comdat_selection_map.get(sel_val, f"UNKNOWN_COMDAT_SELECTION ({sel_val})")
        return aux_dict

    # Format 3: Function Definition / Function-related symbols (.bf, .lf, .ef)
    # Check if parent symbol's Type indicates it's a function (e.g., (Type >> 4) == IMAGE_SYM_DTYPE_FUNCTION)
    # or if StorageClass is IMAGE_SYM_CLASS_FUNCTION (for .bf, .ef symbols)
    is_function_related_parent = ((parent_type >> 4) == dtype_function_val or # Parent is a function symbol
                                 parent_type == getattr(pefile, 'IMAGE_SYM_TYPE_FUNCTION', 0x20) or # Explicit function type
                                 parent_storage_class == sym_class_function) # .bf or .ef symbol
    
    if is_function_related_parent:
        aux_dict["type"] = "Function-related Auxiliary Record"
        # Fields common to function definition aux symbols
        if hasattr(aux_symbol_struct, 'TagIndex'): aux_dict["tag_index_symbol_table"] = aux_symbol_struct.TagIndex # Symbol table index of .bf/.ef
        if hasattr(aux_symbol_struct, 'TotalSize'): aux_dict["total_size_of_function_code"] = aux_symbol_struct.TotalSize
        if hasattr(aux_symbol_struct, 'PointerToLinenumber'): aux_dict["rva_to_linenumber_info"] = hex(aux_symbol_struct.PointerToLinenumber)
        if hasattr(aux_symbol_struct, 'PointerToNextFunction'): aux_dict["symbol_table_index_of_next_function"] = aux_symbol_struct.PointerToNextFunction
        # Fields specific to .lf (line number) or .bf/.ef symbols if they have these attributes
        # Note: pefile might not always parse these distinctly if the aux record is generic.
        if hasattr(aux_symbol_struct, 'Linenumber'): aux_dict["linenumber_for_lf_symbol"] = aux_symbol_struct.Linenumber # For .lf symbols
        # Unused field often zero
        if hasattr(aux_symbol_struct, 'unused'): aux_dict["unused_field"] = aux_symbol_struct.unused
        return aux_dict

    # Format 4: Weak External
    if parent_storage_class == sym_class_weak_external:
        aux_dict["type"] = "Weak External Auxiliary Record"
        if hasattr(aux_symbol_struct, 'TagIndex'): aux_dict["tag_index_of_associated_symbol"] = aux_symbol_struct.TagIndex
        if hasattr(aux_symbol_struct, 'Characteristics'):
            char_val = aux_symbol_struct.Characteristics
            # IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY, IMAGE_WEAK_EXTERN_SEARCH_LIBRARY, IMAGE_WEAK_EXTERN_SEARCH_ALIAS
            weak_extern_char_map = {
                getattr(pefile, 'IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY', 1): "SEARCH_NOLIBRARY (Don't search default libraries)",
                getattr(pefile, 'IMAGE_WEAK_EXTERN_SEARCH_LIBRARY', 2): "SEARCH_LIBRARY (Search default libraries)",
                getattr(pefile, 'IMAGE_WEAK_EXTERN_SEARCH_ALIAS', 3): "SEARCH_ALIAS (Symbol is an alias)"
            }
            aux_dict["characteristics"] = weak_extern_char_map.get(char_val, f"UNKNOWN_WEAK_EXTERN_CHAR ({hex(char_val)})")
        # Unused field
        if hasattr(aux_symbol_struct, 'unused'): aux_dict["unused_field"] = aux_symbol_struct.unused
        return aux_dict
    
    # If none of the above interpretations fit, dump raw or as attributes
    aux_dict["type"] = "Generic or Unknown Auxiliary Record"
    aux_dict["interpretation_status"] = "Could not specifically interpret based on parent symbol; showing raw/generic data."
    raw_bytes = b''
    if isinstance(aux_symbol_struct, bytes): # If we got raw bytes
        raw_bytes = aux_symbol_struct
    elif hasattr(aux_symbol_struct, '__pack__'): # If it's a pefile structure object
        try:
            raw_bytes = aux_symbol_struct.__pack__()
        except Exception: # In case __pack__ fails
            pass # Will try to dump attributes next

    if raw_bytes:
        # Show a snippet of raw hex data if available
        aux_dict["raw_hex_data_snippet"] = raw_bytes[:18].hex() + ("..." if len(raw_bytes) > 18 else "")
    else:
        # If not raw bytes and no __pack__, try to dump attributes of the object
        raw_attributes = {}
        for attr_name in dir(aux_symbol_struct):
            if not attr_name.startswith('_') and not callable(getattr(aux_symbol_struct, attr_name)):
                attr_val = getattr(aux_symbol_struct, attr_name)
                if isinstance(attr_val, int):
                    # Hexify common address/pointer/offset fields
                    if 'Pointer' in attr_name or 'Address' in attr_name or 'Offset' in attr_name or 'Index' in attr_name:
                        raw_attributes[attr_name] = hex(attr_val)
                    else:
                        raw_attributes[attr_name] = attr_val
                elif isinstance(attr_val, bytes):
                    raw_attributes[attr_name] = attr_val.hex()
                else:
                    try: # Try to convert to string, might fail for complex objects
                        raw_attributes[attr_name] = str(attr_val)
                    except:
                        raw_attributes[attr_name] = f"<Unrepresentable attribute: {type(attr_val).__name__}>"
        if raw_attributes:
            aux_dict["generic_attributes"] = raw_attributes
        else:
            aux_dict["data_representation"] = "<Could not represent auxiliary symbol data>"
            
    return aux_dict


def ensure_peid_db_exists(url: str, local_path_str: str, verbose: bool = False) -> bool:
    """
    Ensures the PEiD database file exists at local_path.
    If not, attempts to download it from the given URL.

    Args:
        url: URL to download the PEiD database from.
        local_path_str: String path where the database should be/is stored.
        verbose: If True, prints more detailed status messages.

    Returns:
        True if the database exists or was successfully downloaded, False otherwise.
    """
    local_path = Path(local_path_str) # Convert to Path object for easier handling
    if local_path.exists() and local_path.is_file() and local_path.stat().st_size > 0: # Check if non-empty file
        if verbose: logger.info(f"PEiD database already exists and is non-empty at: {local_path}")
        return True

    if not REQUESTS_AVAILABLE:
        logger.error("'requests' library not found. Cannot download PEiD database.")
        safe_print("[!] 'requests' library not found. Cannot download PEiD database.", verbose_prefix=" ")
        return False

    logger.info(f"PEiD database not found or empty at '{local_path}'. Attempting download from '{url}'...")
    safe_print(f"[*] PEiD database not found/empty at {local_path}. Attempting download from {url}...", verbose_prefix=" ")
    
    try:
        # Ensure parent directory exists
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Perform the download
        # Use a timeout for the request
        response = requests.get(url, timeout=20, stream=True) # stream=True for potentially large files
        response.raise_for_status() # Raises HTTPError for bad responses (4XX or 5XX)

        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192): # Write in chunks
                f.write(chunk)
        
        if local_path.stat().st_size > 0: # Verify download resulted in a non-empty file
            logger.info(f"PEiD database successfully downloaded to: {local_path}")
            safe_print(f"[*] PEiD database successfully downloaded to: {local_path}", verbose_prefix=" ")
            return True
        else:
            logger.error(f"PEiD database downloaded but is empty: {local_path}")
            safe_print(f"[!] PEiD database downloaded but is empty: {local_path}", verbose_prefix=" ")
            try: os.remove(local_path) # Clean up empty file
            except OSError: pass
            return False

    except requests.exceptions.RequestException as e_req:
        logger.error(f"Error downloading PEiD database from {url}: {e_req}")
        safe_print(f"[!] Error downloading PEiD database: {e_req}", verbose_prefix=" ")
        if local_path.exists(): # Clean up partial download if it exists
            try: os.remove(local_path)
            except OSError: pass
        return False
    except IOError as e_io:
        logger.error(f"Error saving PEiD database to {local_path}: {e_io}")
        safe_print(f"[!] Error saving PEiD database to {local_path}: {e_io}", verbose_prefix=" ")
        return False
    except Exception as e_gen: # Catch-all for other unexpected errors
        logger.error(f"Unexpected error during PEiD DB download/save: {e_gen}", exc_info=verbose)
        safe_print(f"[!] Unexpected error ensuring PEiD DB: {e_gen}", verbose_prefix=" ")
        if local_path.exists():
            try: os.remove(local_path)
            except OSError: pass
        return False


def ensure_capa_rules_exist(rules_base_dir_str: str, rules_zip_url: str, verbose: bool = False) -> Optional[str]:
    """
    Ensures Capa rules exist in the specified base directory, under a 'rules' subdirectory.
    If not, attempts to download from rules_zip_url, extract, and organize them.
    The expected structure after download/extraction is: rules_base_dir / CAPA_RULES_SUBDIR_NAME / <actual_rules>

    Args:
        rules_base_dir_str: The base directory where capa rules should be stored (e.g., .../capa_rules_store).
        rules_zip_url: URL of the capa-rules zip file (e.g., a GitHub release).
        verbose: If True, enables more detailed logging.

    Returns:
        The absolute path to the 'rules' subdirectory (e.g., .../capa_rules_store/rules) if successful,
        None otherwise.
    """
    rules_base_dir = Path(rules_base_dir_str).resolve() # Ensure absolute path
    final_rules_target_path = rules_base_dir / CAPA_RULES_SUBDIR_NAME # e.g. .../capa_rules_store/rules

    # Check if rules already exist and the target directory is not empty
    if final_rules_target_path.is_dir() and any(final_rules_target_path.iterdir()):
        if verbose: logger.info(f"Capa rules already available and non-empty at: {final_rules_target_path}")
        return str(final_rules_target_path)

    if not REQUESTS_AVAILABLE:
        logger.error("'requests' library not found. Cannot download capa rules.")
        return None

    logger.info(f"Capa rules not found or empty at '{final_rules_target_path}'. Attempting to download and extract to '{rules_base_dir}'...")

    try:
        rules_base_dir.mkdir(parents=True, exist_ok=True) # Ensure base directory exists
        zip_path = rules_base_dir / "capa-rules-download.zip" # Temporary zip file path
        
        # Path to the directory created by unzipping (e.g., capa-rules-X.Y.Z)
        # We need to discover this name after extraction.
        extracted_top_level_dir_path: Optional[Path] = None

        # Download the zip file
        logger.info(f"Downloading capa rules from {rules_zip_url} to {zip_path}...")
        response = requests.get(rules_zip_url, timeout=60, stream=True) # Increased timeout for large rulesets
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192 * 4): # Larger chunk size
                f.write(chunk)
        logger.info("Capa rules zip downloaded successfully.")

        # Extract the zip file
        logger.info(f"Extracting capa rules from {zip_path} into {rules_base_dir}...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Determine the name of the top-level directory inside the zip
            # Assumes capa-rules zip has a single top-level directory like 'capa-rules-vX.Y.Z/'
            # or similar, containing the actual 'rules' and 'sigs' folders.
            namelist = zip_ref.namelist()
            if not namelist:
                raise RulesAccessError("Downloaded capa rules zip file is empty.")
            
            # Find the common prefix directory (e.g., "capa-rules-X.Y.Z/")
            # This is usually the first entry if it's a directory.
            potential_toplevel_dir_in_zip = ""
            first_entry = namelist[0]
            if '/' in first_entry: # e.g., "capa-rules-main/README.md" -> "capa-rules-main/"
                potential_toplevel_dir_in_zip = first_entry.split('/', 1)[0]
            
            if not potential_toplevel_dir_in_zip:
                 raise RulesAccessError("Could not determine the top-level directory name within the capa rules zip.")

            # Extract all files
            zip_ref.extractall(rules_base_dir)
            extracted_top_level_dir_path = rules_base_dir / potential_toplevel_dir_in_zip
            
            if not extracted_top_level_dir_path.is_dir():
                raise RulesAccessError(f"Extraction failed or top-level directory '{extracted_top_level_dir_path.name}' not found in '{rules_base_dir}'.")
            
        logger.info(f"Capa rules extracted successfully from zip to '{extracted_top_level_dir_path}'.")

        # Now, we need to move the *contents* of extracted_top_level_dir_path/rules
        # to final_rules_target_path (e.g., rules_base_dir/CAPA_RULES_SUBDIR_NAME)
        # Or, if the extracted dir *is* the 'rules' dir, move that.
        # The capa-rules releases typically have a structure like:
        # capa-rules-vX.Y.Z/
        #  +- rules/
        #  +- sigs/ (optional)
        #  +- lib/ (optional)
        #  +- ... (other files)
        # We want the contents of capa-rules-vX.Y.Z/rules/ into our final_rules_target_path.

        source_rules_dir_within_extraction = extracted_top_level_dir_path / CAPA_RULES_SUBDIR_NAME # e.g. .../capa-rules-X.Y.Z/rules
        
        if not source_rules_dir_within_extraction.is_dir():
            # Fallback: maybe the extracted_top_level_dir_path *is* the 'rules' directory itself
            # (less common for official capa-rules zips but possible for custom ones)
            if extracted_top_level_dir_path.name == CAPA_RULES_SUBDIR_NAME:
                source_rules_dir_within_extraction = extracted_top_level_dir_path
            else:
                raise RulesAccessError(f"The '{CAPA_RULES_SUBDIR_NAME}' subdirectory was not found within the extracted capa rules at '{extracted_top_level_dir_path}'.")

        # Ensure final_rules_target_path is clean before moving
        if final_rules_target_path.exists():
            logger.warning(f"Target rules directory '{final_rules_target_path}' already exists. Removing it before placing newly extracted rules.")
            try:
                shutil.rmtree(final_rules_target_path)
            except Exception as e_rm_old:
                raise RulesAccessError(f"Failed to remove existing target rules directory '{final_rules_target_path}': {e_rm_old}") from e_rm_old
        
        final_rules_target_path.mkdir(parents=True, exist_ok=True) # Create if doesn't exist (e.g. after rmtree)

        logger.info(f"Moving rules from '{source_rules_dir_within_extraction}' to '{final_rules_target_path}'...")
        # Move each item from source_rules_dir_within_extraction to final_rules_target_path
        # This handles cases where final_rules_target_path might be the same as source_rules_dir_within_extraction's parent
        # and avoids shutil.move issues with moving a dir into itself.
        for item in source_rules_dir_within_extraction.iterdir():
            try:
                shutil.move(str(item), str(final_rules_target_path / item.name))
            except Exception as e_mv_item:
                 raise RulesAccessError(f"Failed to move item '{item.name}' from '{source_rules_dir_within_extraction}' to '{final_rules_target_path}': {e_mv_item}") from e_mv_item


        if final_rules_target_path.is_dir() and any(final_rules_target_path.iterdir()):
            logger.info(f"Capa rules now correctly organized at: {final_rules_target_path}")
            return str(final_rules_target_path)
        else:
            raise RulesAccessError(f"Capa rules were processed, but the final target directory '{final_rules_target_path}' is still not found or is empty.")

    except requests.exceptions.RequestException as e_req_capa:
        logger.error(f"Error downloading capa rules from {rules_zip_url}: {e_req_capa}")
    except zipfile.BadZipFile:
        logger.error(f"Error: Downloaded capa rules file '{zip_path}' is not a valid zip file or is corrupted.")
    except RulesAccessError as e_rules_access: # Catch our custom error
        logger.error(f"Capa rules access error: {e_rules_access}")
    except Exception as e_gen_capa:
        logger.error(f"An unexpected error occurred during capa rules download/extraction/organization: {e_gen_capa}", exc_info=verbose)
    finally:
        # Clean up downloaded zip file
        if 'zip_path' in locals() and zip_path.exists(): # Check if zip_path was defined and exists
            try:
                os.remove(zip_path)
                if verbose: logger.info(f"Cleaned up downloaded zip: {zip_path}")
            except OSError as e_rm_zip:
                logger.warning(f"Could not remove downloaded capa rules zip '{zip_path}': {e_rm_zip}")
        # Clean up the (now likely empty) top-level extracted directory if it's different from rules_base_dir
        if 'extracted_top_level_dir_path' in locals() and \
           extracted_top_level_dir_path and \
           extracted_top_level_dir_path.exists() and \
           extracted_top_level_dir_path != rules_base_dir: # Avoid deleting base if it was the direct target
            try:
                shutil.rmtree(extracted_top_level_dir_path)
                if verbose: logger.info(f"Cleaned up temporary extraction directory: {extracted_top_level_dir_path}")
            except Exception as e_rm_extract_dir:
                logger.warning(f"Could not remove temporary capa extraction directory '{extracted_top_level_dir_path}': {e_rm_extract_dir}")
    return None # Return None if any error occurred


def parse_signature_file(db_path_str: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Parses a PEiD-like signature file (userdb.txt format).

    Args:
        db_path_str: Path to the signature database file.
        verbose: If True, enables detailed logging of parsing.

    Returns:
        A list of signature dictionaries. Each dictionary contains:
        'name': (str) Signature name.
        'ep_only': (bool) True if signature applies only at entry point.
        'regex_pattern': (compiled re.Pattern) Compiled regex for the signature pattern.
                         None if pattern is invalid or not regex-based.
        'pattern_bytes': (List[Optional[int]]) Byte pattern with None for wildcards '??'.
                         This is kept for potential non-regex matching in future, but regex is primary.
    """
    db_path = Path(db_path_str)
    if verbose: logger.info(f"Starting to parse PEiD-like signature file: {db_path}")
    
    signatures: List[Dict[str, Any]] = []
    current_signature: Optional[Dict[str, Any]] = None

    try:
        with db_path.open('r', encoding='utf-8', errors='ignore') as f:
            for line_num, line_content in enumerate(f, 1):
                line = line_content.strip()
                if not line or line.startswith(';'): # Skip empty lines and comments
                    continue

                name_match = re.match(r'^\[(.*)\]$', line) # Match signature name, e.g., [Compiler Name]
                if name_match:
                    # If a previous signature was being built, add it to the list
                    if current_signature and 'name' in current_signature and \
                       (current_signature.get('regex_pattern') or current_signature.get('pattern_bytes')):
                        signatures.append(current_signature)
                    
                    # Start a new signature
                    current_signature = {
                        'name': name_match.group(1).strip(),
                        'ep_only': False, # Default to False
                        'regex_pattern': None,
                        'pattern_bytes': [] # For storing byte representation if needed
                    }
                    if verbose: logger.debug(f"  [PEiD Parse] Line {line_num}: New signature section '{current_signature['name']}'")
                    continue

                if current_signature: # Only process if we are inside a signature block
                    sig_pattern_match = re.match(r'^signature\s*=\s*(.*)', line, re.IGNORECASE)
                    if sig_pattern_match:
                        pattern_str_hex = sig_pattern_match.group(1).strip().upper()
                        hex_byte_tokens = pattern_str_hex.split()
                        
                        byte_pattern_list_for_storage: List[Optional[int]] = []
                        regex_byte_components_for_compile: List[bytes] = []
                        is_valid_pattern = True

                        for token in hex_byte_tokens:
                            if token == '??': # Wildcard byte
                                byte_pattern_list_for_storage.append(None)
                                regex_byte_components_for_compile.append(b'.') # Regex: matches any character (except newline by default)
                            elif len(token) == 2 and all(c in '0123456789ABCDEF' for c in token): # Valid hex byte
                                try:
                                    byte_val = int(token, 16)
                                    byte_pattern_list_for_storage.append(byte_val)
                                    regex_byte_components_for_compile.append(re.escape(bytes([byte_val]))) # Escape for regex
                                except ValueError:
                                    is_valid_pattern = False; break
                            # PEiD also supports nibble wildcards like 'F?' or '?F'
                            elif len(token) == 2 and (token[0] == '?' or token[1] == '?'):
                                byte_pattern_list_for_storage.append(None) # Treat as full wildcard for byte list
                                # For regex, construct pattern like b'[\\x00-\\x0F]' for '?F' or b'[\\xF0-\\xFF]' for 'F?'
                                # This is more precise than just '.', but '.' is simpler for now and often sufficient.
                                # Using '.' for simplicity, can be enhanced if needed.
                                # Example for '?F': regex_byte_components_for_compile.append(b"[\\x00-\\x0F%s]" % token[1].encode('ascii'))
                                # Example for 'F?': regex_byte_components_for_compile.append(b"[\\x%s0-\\x%sF]" % (token[0].encode('ascii'), token[0].encode('ascii')))
                                # Current: simplified to treat as full wildcard for regex too
                                regex_byte_components_for_compile.append(b'.') # Simplified for now
                            else: # Invalid token
                                is_valid_pattern = False; break
                        
                        if is_valid_pattern and regex_byte_components_for_compile:
                            current_signature['pattern_bytes'] = byte_pattern_list_for_storage
                            try:
                                current_signature['regex_pattern'] = re.compile(b''.join(regex_byte_components_for_compile))
                                if verbose: logger.debug(f"    [PEiD Parse] Line {line_num}: Parsed signature pattern for '{current_signature['name']}'")
                            except re.error as e_re_compile:
                                logger.warning(f"    [PEiD Parse] Line {line_num}: Regex compilation error for '{current_signature['name']}': {e_re_compile}. Pattern: '{pattern_str_hex}'")
                                current_signature['regex_pattern'] = None # Invalidate on error
                        else:
                            if verbose: logger.warning(f"    [PEiD Parse] Line {line_num}: Invalid signature pattern for '{current_signature['name']}': '{pattern_str_hex}'")
                            # Invalidate current signature if pattern is bad
                            current_signature = None # Or just clear pattern fields: current_signature['regex_pattern'] = None; current_signature['pattern_bytes'] = []
                        continue # Move to next line

                    ep_only_match = re.match(r'^ep_only\s*=\s*(true|false)', line, re.IGNORECASE)
                    if ep_only_match:
                        current_signature['ep_only'] = ep_only_match.group(1).lower() == 'true'
                        if verbose: logger.debug(f"    [PEiD Parse] Line {line_num}: Set ep_only={current_signature['ep_only']} for '{current_signature['name']}'")
                        
        # Add the last parsed signature if it's valid
        if current_signature and 'name' in current_signature and \
           (current_signature.get('regex_pattern') or current_signature.get('pattern_bytes')):
            signatures.append(current_signature)

    except FileNotFoundError:
        logger.error(f"PEiD signature database not found at: {db_path}")
        safe_print(f"[!] PEiD DB not found: {db_path}") # User-facing message
        return [] # Return empty list
    except Exception as e_parse_sig:
        logger.error(f"Error parsing PEiD signature database {db_path}: {e_parse_sig}", exc_info=verbose)
        safe_print(f"[!] Error parsing PEiD DB {db_path}: {e_parse_sig}")
        return []

    if verbose: logger.info(f"Successfully loaded {len(signatures)} PEiD signatures from {db_path}.")
    return signatures


def find_pattern_in_data_regex(data_block: bytes, signature_dict: Dict[str, Any], 
                               verbose: bool = False, section_name_for_log: str = "UnknownSection") -> Optional[str]:
    """
    Searches for a pre-compiled regex pattern (from signature_dict) within a data block.

    Args:
        data_block: The bytes data to search within.
        signature_dict: A dictionary for a signature, expected to have 'regex_pattern' (compiled re.Pattern)
                        and 'name' (str).
        verbose: If True, logs match details.
        section_name_for_log: Name of the data block/section for logging purposes.

    Returns:
        The name of the signature if matched, otherwise None.
    """
    regex_pattern = signature_dict.get('regex_pattern')
    pattern_name = signature_dict.get('name', "UnnamedPattern")

    if not regex_pattern or not data_block: # Skip if no pattern or no data
        return None

    try:
        match = regex_pattern.search(data_block) # Perform the regex search
        if match:
            if verbose: 
                logger.debug(f"  [PEiD Match] Pattern '{pattern_name}' matched via REGEX at offset {hex(match.start())} within '{section_name_for_log}'.")
            return pattern_name # Return signature name on match
    except Exception as e_re_search: # Catch any unexpected error during regex search
        if verbose: 
            logger.warning(f"  [PEiD Regex Error] Error searching for pattern '{pattern_name}' in '{section_name_for_log}': {e_re_search}", exc_info=verbose)
    return None


def perform_yara_scan(filepath: str, file_data: bytes, 
                      yara_rules_path_str: Optional[str], 
                      yara_available_flag: bool, 
                      verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Performs a YARA scan on the given file data using rules from yara_rules_path.

    Args:
        filepath: Original path of the scanned file (for context).
        file_data: The byte content of the file to scan.
        yara_rules_path_str: Path to a YARA rule file or a directory of .yar/.yara files.
                             Expected to be an absolute path if provided.
        yara_available_flag: Boolean indicating if the 'yara-python' library is available.
        verbose: If True, enables detailed logging.

    Returns:
        A list of dictionaries, where each dictionary represents a YARA match.
        Returns an empty list if no matches or if YARA is unavailable/rules are missing.
        If an error occurs, the list may contain a single dictionary with an "error" key.
    """
    scan_results: List[Dict[str, Any]] = []

    if not yara_available_flag:
        logger.warning("YARA scan: 'yara-python' library not found or failed to import. Skipping YARA scan.")
        # OPTIONAL_DEPENDENCY_IMPORT_ERRORS might have more details if yara is in DEPENDENCIES
        yara_import_err = OPTIONAL_DEPENDENCY_IMPORT_ERRORS.get("yara-python", "Import failed or library not specified in checks.")
        if verbose: logger.debug(f"  [YARA Scan Debug] Detailed YARA import error: {yara_import_err}")
        scan_results.append({"status": "skipped", "reason": "yara-python library not available", "details": yara_import_err})
        return scan_results

    if not yara_rules_path_str:
        logger.info("YARA scan: No YARA rules path provided. Skipping YARA scan.")
        scan_results.append({"status": "skipped", "reason": "No YARA rules path provided."})
        return scan_results

    yara_rules_path = Path(yara_rules_path_str) # Convert to Path object

    try:
        if verbose: logger.info(f"YARA scan: Loading rules from: {yara_rules_path}")
        
        rules: Optional[yara.Rules] = None
        if yara_rules_path.is_dir():
            # Compile rules from a directory: need to create a dictionary of {namespace: filepath}
            # Yara namespaces default to filename without extension if not specified in rule.
            # For simplicity, we'll let yara handle namespaces based on filenames.
            filepaths_for_yara_compile: Dict[str, str] = {}
            rule_files_found = list(yara_rules_path.glob('**/*.yar')) + list(yara_rules_path.glob('**/*.yara'))
            
            if not rule_files_found:
                logger.warning(f"YARA scan: No .yar or .yara files found in directory: {yara_rules_path}")
                scan_results.append({"status": "skipped", "reason": f"No YARA rule files found in '{yara_rules_path}'."})
                return scan_results

            for rf_path in rule_files_found:
                # Use filename as a simple namespace key; yara might override with 'include' or rule namespaces
                namespace_key = rf_path.stem 
                filepaths_for_yara_compile[namespace_key] = str(rf_path)
            
            if verbose: logger.debug(f"  [YARA Scan Debug] Compiling rules from filepaths: {filepaths_for_yara_compile}")
            rules = yara.compile(filepaths=filepaths_for_yara_compile)

        elif yara_rules_path.is_file():
            if verbose: logger.debug(f"  [YARA Scan Debug] Compiling single rule file: {yara_rules_path}")
            rules = yara.compile(filepath=str(yara_rules_path))
        else:
            logger.warning(f"YARA scan: YARA rules path is not a valid file or directory: {yara_rules_path}")
            scan_results.append({"status": "error", "reason": f"Invalid YARA rules path '{yara_rules_path}'."})
            return scan_results

        if not rules: # Should be caught by earlier checks, but as a safeguard
             logger.error("YARA scan: Rules object is None after compile attempt. This should not happen.")
             scan_results.append({"status": "error", "reason": "YARA rules compilation unexpectedly resulted in None."})
             return scan_results

        logger.info(f"YARA scan: Rules compiled successfully. Scanning data from '{filepath}' (size: {len(file_data)} bytes).")
        matches = rules.match(data=file_data) # Perform the scan on the byte data

        if matches:
            logger.info(f"YARA scan: {len(matches)} YARA rule(s) matched.")
            for match_obj in matches:
                match_detail: Dict[str, Any] = {
                    "rule_name": match_obj.rule,
                    "namespace": match_obj.namespace if match_obj.namespace and match_obj.namespace != 'default' else "default",
                    "tags": list(match_obj.tags) if match_obj.tags else [],
                    "meta": dict(match_obj.meta) if match_obj.meta else {},
                    "strings": []
                }
                if match_obj.strings:
                    for s_match_instance in match_obj.strings:
                        # s_match_instance is usually a tuple: (offset, identifier, data_matched)
                        # identifier is like '$a', '$string1'
                        # data_matched is the actual bytes that matched
                        str_offset = s_match_instance[0]
                        str_identifier = s_match_instance[1]
                        str_data_bytes = s_match_instance[2]
                        
                        # Try to decode matched bytes for display, with fallbacks
                        try:
                            # Attempt UTF-8 first, then Latin-1 as a common fallback
                            str_data_repr = str_data_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                str_data_repr = str_data_bytes.decode('latin-1')
                            except UnicodeDecodeError:
                                # If all decodes fail, use a hex representation
                                str_data_repr = str_data_bytes.hex()
                        
                        # Truncate very long string representations for readability in results
                        if len(str_data_repr) > 128: # Increased limit slightly
                            str_data_repr = str_data_repr[:125] + "..."
                        
                        match_detail["strings"].append({
                            "offset": hex(str_offset),
                            "identifier": str_identifier,
                            "matched_data_repr": str_data_repr
                        })
                scan_results.append(match_detail)
        else:
            logger.info("YARA scan: No YARA matches found.")
            scan_results.append({"status": "no_matches", "reason": "Scan completed, no rules matched."})

    except yara.Error as e_yara: # Catch YARA-specific errors (compile, match)
        logger.error(f"YARA scan: YARA library error: {e_yara}")
        scan_results.append({"status": "error", "reason": f"YARA Error: {str(e_yara)}"})
    except FileNotFoundError as e_fnf: # If a rule file path itself is broken during compilation
        logger.error(f"YARA scan: File not found during rule processing: {e_fnf}")
        scan_results.append({"status": "error", "reason": f"YARA rule file not found: {str(e_fnf)}"})
    except Exception as e_gen_yara:
        logger.error(f"YARA scan: Unexpected error during YARA scan: {e_gen_yara}", exc_info=verbose)
        scan_results.append({"status": "error", "reason": f"Unexpected YARA scan error: {str(e_gen_yara)}"})
        
    return scan_results

def _parse_capa_analysis(pe_obj: pefile.PE, # pe_obj is now passed but might not be directly used if capa works from filepath
                         pe_filepath_original: str,
                         capa_rules_dir_path_arg: Optional[str], # User-provided path from args
                         capa_sigs_dir_path_arg: Optional[str],  # User-provided path from args
                         verbose: bool) -> Dict[str, Any]:
    """
    Performs capability analysis using the 'capa' library.
    It attempts to use capa's main internal workflow by simulating CLI arguments.

    Args:
        pe_obj: The pefile.PE object (may be used by some capa extractors, though filepath is primary).
        pe_filepath_original: The absolute path to the PE file being analyzed.
        capa_rules_dir_path_arg: User-specified path to capa rules directory.
        capa_sigs_dir_path_arg: User-specified path to capa signatures directory.
        verbose: If True, enables more detailed logging from this function and capa.

    Returns:
        A dictionary containing the capa analysis results, status, and any errors.
        Structure:
        {
            "status": "Not performed" | "Capa library components not available." | "Capa rules not found..." | "Analysis complete (adapted workflow)" | "Error during analysis...",
            "error": Optional[str],
            "results": Optional[Dict] (The JSON-like structure from capa's ResultDocument)
        }
    """
    capa_results: Dict[str, Any] = {"status": "Not performed", "error": None, "results": None}

    if not CAPA_AVAILABLE: # Check the global flag
        capa_results["status"] = "Capa library components not available."
        capa_results["error"] = f"Capa import error: {CAPA_IMPORT_ERROR if CAPA_IMPORT_ERROR else 'Unknown import failure.'}"
        logger.warning(f"Capa analysis: Capa components not available. Error: {capa_results['error']}")
        return capa_results

    # --- Resolve Capa Rules Path ---
    # effective_rules_path_str will be the path capa actually tries to use.
    effective_rules_path_str: Optional[str] = None
    if capa_rules_dir_path_arg: # User provided a path
        resolved_arg_path = Path(capa_rules_dir_path_arg).resolve()
        if resolved_arg_path.is_dir() and any(resolved_arg_path.iterdir()):
            effective_rules_path_str = str(resolved_arg_path)
            logger.info(f"Capa analysis: Using user-provided capa rules directory: {effective_rules_path_str}")
        else:
            logger.warning(f"Capa analysis: User-provided capa_rules_dir '{capa_rules_dir_path_arg}' is invalid or empty. Attempting script-relative default.")
            # Fall through to default logic if user path is bad
    
    if not effective_rules_path_str: # If no valid user path, try default
        default_rules_base = SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME
        logger.info(f"Capa analysis: Attempting to use/ensure default capa rules at base: '{default_rules_base}'")
        # ensure_capa_rules_exist returns the path to the 'rules' subdir, e.g., .../capa_rules_store/rules
        effective_rules_path_str = ensure_capa_rules_exist(str(default_rules_base), CAPA_RULES_ZIP_URL, verbose)

    if not effective_rules_path_str: # If still no rules path after trying default
        err_path_msg_part = capa_rules_dir_path_arg if capa_rules_dir_path_arg else str(SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME / CAPA_RULES_SUBDIR_NAME)
        capa_results["status"] = "Capa rules not found or download/extraction failed."
        capa_results["error"] = f"Failed to ensure capa rules at or via '{err_path_msg_part}'. Check logs from ensure_capa_rules_exist."
        logger.error(capa_results["error"])
        return capa_results
    else:
        logger.info(f"Capa analysis: Will use capa rules from: {effective_rules_path_str}")

    # --- Resolve Capa Signatures Path ---
    effective_capa_sigs_path_str_for_mock_args: Optional[str] = None # Path to pass to capa
    if capa_sigs_dir_path_arg:
        resolved_sigs_arg_path = Path(capa_sigs_dir_path_arg).resolve()
        if resolved_sigs_arg_path.is_dir():
            effective_capa_sigs_path_str_for_mock_args = str(resolved_sigs_arg_path)
            logger.info(f"Capa analysis: Using user-provided Capa signatures directory: {effective_capa_sigs_path_str_for_mock_args}")
        else:
            logger.warning(f"Capa analysis: User-provided capa_sigs_dir '{capa_sigs_dir_path_arg}' is not a valid directory. Will try defaults.")
            # Fall through to default logic
            
    if not effective_capa_sigs_path_str_for_mock_args: # If no valid user path for sigs
        # Try script-relative 'capa_sigs'
        potential_script_relative_sigs = SCRIPT_DIR / "capa_sigs"
        if potential_script_relative_sigs.is_dir() and any(potential_script_relative_sigs.iterdir()):
             effective_capa_sigs_path_str_for_mock_args = str(potential_script_relative_sigs.resolve())
             logger.info(f"Capa analysis: Found and using script-relative 'capa_sigs' directory: {effective_capa_sigs_path_str_for_mock_args}")
        else:
            # Try sigs directory next to the resolved rules (common for capa-rules releases)
            # effective_rules_path_str is like ".../capa_rules_store/rules"
            # So, sigs would be at ".../capa_rules_store/sigs"
            potential_sigs_near_rules = Path(effective_rules_path_str).parent / "sigs"
            if potential_sigs_near_rules.is_dir() and any(potential_sigs_near_rules.iterdir()):
                effective_capa_sigs_path_str_for_mock_args = str(potential_sigs_near_rules.resolve())
                logger.info(f"Capa analysis: Found 'sigs' directory near resolved rules store: {effective_capa_sigs_path_str_for_mock_args}")
            else:
                logger.warning("Capa analysis: Capa signatures directory not found locally (e.g., ./capa_sigs or next to rules). "
                               "Capa will attempt to use its internal default signatures path if available, "
                               "or no library function signatures will be loaded if that path is problematic or empty. "
                               "For explicit control, provide --capa-sigs-dir or ensure a 'capa_sigs' folder.")
                # Let capa handle its default if we don't find one.
                # Passing an empty string or None to capa.main.get_signatures often means "use default".
                # If capa's default is problematic (e.g. permissions), it might error.
                effective_capa_sigs_path_str_for_mock_args = None # Let capa decide its default

    # --- Simulate Capa CLI Arguments for capa.main workflow ---
    class MockCapaCliArgs: pass # Simple namespace class
    mock_args = MockCapaCliArgs()
    
    # Basic required args
    mock_args.input_file = Path(pe_filepath_original) # Must be a Path object
    mock_args.rules = [Path(effective_rules_path_str)] # Must be a list of Path objects
    
    # Set format, backend, os - use capa's constants if possible
    mock_args.format = getattr(capa.features.common, 'FORMAT_PE', 'pe')
    mock_args.backend = getattr(capa.loader, 'BACKEND_AUTO', 'auto') # Let capa auto-detect backend for PE
    mock_args.os = getattr(capa.features.common, 'OS_WINDOWS', 'windows') # Assume Windows for PE files

    # Signatures path
    if effective_capa_sigs_path_str_for_mock_args:
        mock_args.signatures = Path(effective_capa_sigs_path_str_for_mock_args)
    else:
        # If we couldn't find a local sigs path, tell capa to use its default.
        # capa.main.get_signatures handles None or "" by trying its internal default.
        mock_args.signatures = None # Or "" - check capa's preference for "use default"

    # Other common args capa.main might expect or use for metadata
    mock_args.tag = None # No specific tag filtering by default
    mock_args.verbose = verbose # For capa's own verbosity
    mock_args.vverbose = False # Not enabling capa's very verbose mode by default
    mock_args.json = True # We want JSON-like output (ResultDocument)
    mock_args.color = "never" # No ANSI color codes in JSON output
    mock_args.debug = verbose # Link capa debug to our verbose flag
    mock_args.quiet = not verbose
    
    # Ensure these exist, even if empty, as capa.main might access them
    if not hasattr(mock_args, 'restrict_to_functions'): setattr(mock_args, 'restrict_to_functions', [])
    if not hasattr(mock_args, 'restrict_to_processes'): setattr(mock_args, 'restrict_to_processes', [])
    if not hasattr(mock_args, 'is_default_rules'): setattr(mock_args, 'is_default_rules', (capa_rules_dir_path_arg is None))
    if not hasattr(mock_args, 'is_default_signatures'):
        is_sigs_default = (capa_sigs_dir_path_arg is None and effective_capa_sigs_path_str_for_mock_args is None)
        setattr(mock_args, 'is_default_signatures', is_sigs_default)


    try:
        if verbose:
            sig_val_log = str(mock_args.signatures) if mock_args.signatures else "Capa Default"
            rules_val_log_list = [str(r) for r in mock_args.rules]
            logger.info(f"  [Capa Pre-Analysis] Mocked CLI args for capa.main: input_file='{mock_args.input_file}', "
                        f"rules={rules_val_log_list}, format='{mock_args.format}', backend='{mock_args.backend}', "
                        f"os='{mock_args.os}', signatures='{sig_val_log}'")

        # --- Execute Capa's main analysis stages ---
        # These calls mimic what `capa.main.main()` does internally.
        # Error handling for each step is important.

        # 1. Handle common args (logging, etc.) - may not be strictly needed if we control logging
        if hasattr(capa.main, 'handle_common_args'):
            capa.main.handle_common_args(mock_args)

        # 2. Ensure input file exists (already done by us, but good for capa's internal state)
        if hasattr(capa.main, 'ensure_input_exists_from_cli'):
            capa.main.ensure_input_exists_from_cli(mock_args) # Can raise FileNotFoundError

        # 3. Get input format (already set, but capa might refine)
        input_format_resolved = mock_args.format
        if hasattr(capa.main, 'get_input_format_from_cli'):
            input_format_resolved = capa.main.get_input_format_from_cli(mock_args)
        mock_args.format = input_format_resolved # Update mock_args

        # 4. Load rules
        # This can raise InvalidRule, RulesAccessError, etc.
        loaded_rules = capa.main.get_rules_from_cli(mock_args)
        rule_count_str = str(len(loaded_rules.rules)) if hasattr(loaded_rules, 'rules') and hasattr(loaded_rules.rules, '__len__') else 'N/A'
        logger.info(f"Capa analysis: Rules loaded via capa.main.get_rules_from_cli. Rule count: {rule_count_str}")

        # 5. Get backend (already set to auto, capa might refine)
        backend_resolved = mock_args.backend
        if hasattr(capa.main, 'get_backend_from_cli'):
            backend_resolved = capa.main.get_backend_from_cli(mock_args, input_format_resolved)
        mock_args.backend = backend_resolved # Update mock_args

        # 6. Get OS (already set, capa might refine)
        if hasattr(capa.main, 'get_os_from_cli'):
            mock_args.os = capa.main.get_os_from_cli(mock_args, backend_resolved)

        # 7. Get extractor
        # This is a critical step and can raise various Unsupported*Error exceptions.
        extractor = capa.main.get_extractor_from_cli(mock_args, input_format_resolved, backend_resolved)
        logger.info(f"Capa analysis: Extractor obtained: {type(extractor).__name__}")

        # 8. Find capabilities
        # This is the core analysis step.
        logger.info("Capa analysis: Starting capability detection...")
        capabilities_matches = capa.capabilities.common.find_capabilities(loaded_rules, extractor, disable_progress=True)
        logger.info("Capa analysis: Capability detection complete.")
        
        # 9. Collect metadata for the report
        # Construct a simulated argv for capa's metadata collection
        simulated_argv_for_meta = ["PeMCP.py_capa_tool", str(mock_args.input_file)] # Basic argv

        # Ensure mock_args.rules is List[Path] for collect_metadata
        actual_rule_paths_for_meta_arg = mock_args.rules
        if not (isinstance(actual_rule_paths_for_meta_arg, list) and \
                all(isinstance(p, Path) for p in actual_rule_paths_for_meta_arg)):
            logger.warning(f"Capa analysis: Rules paths for capa.loader.collect_metadata "
                           f"('mock_args.rules': {actual_rule_paths_for_meta_arg}) are not List[Path] as expected. "
                           "Attempting conversion or using empty list. Metadata might be incomplete.")
            temp_paths_for_meta = []
            all_valid_paths = True
            if isinstance(actual_rule_paths_for_meta_arg, list):
                for p_item in actual_rule_paths_for_meta_arg:
                    if isinstance(p_item, Path): temp_paths_for_meta.append(p_item)
                    elif isinstance(p_item, str) and Path(p_item).exists(): temp_paths_for_meta.append(Path(p_item))
                    else: all_valid_paths = False; break
            else: all_valid_paths = False
            actual_rule_paths_for_meta_arg = temp_paths_for_meta if all_valid_paths else []


        meta_for_report = capa.loader.collect_metadata(
            argv=simulated_argv_for_meta,
            input_path=mock_args.input_file, # Path object
            input_format=input_format_resolved,
            os_name=mock_args.os,
            rules_paths=actual_rule_paths_for_meta_arg, # Must be List[Path]
            extractor=extractor,
            capabilities_matches=capabilities_matches # The result from find_capabilities
        )
        
        # Compute layout if necessary (newer capa versions might do this in collect_metadata or ResultDocument)
        if hasattr(meta_for_report, 'analysis') and hasattr(capabilities_matches, 'matches') and \
           hasattr(meta_for_report.analysis, 'layout') and hasattr(capa.loader, 'compute_layout'):
            # This assumes capabilities_matches is the direct result from find_capabilities,
            # which should have a .matches attribute (dictionary of rule_name -> list of match locations)
            if isinstance(capabilities_matches.matches, dict):
                 meta_for_report.analysis.layout = capa.loader.compute_layout(loaded_rules, extractor, capabilities_matches.matches)
            else:
                 logger.warning("Capa analysis: capabilities_matches.matches is not a dict, cannot compute layout.")


        # 10. Create the ResultDocument (JSON-like structure)
        # The `capabilities_matches.matches` should be the dictionary of rule names to match locations.
        if not isinstance(capabilities_matches.matches, dict):
            logger.error(f"Capa analysis: Expected capabilities_matches.matches to be a dict, but got {type(capabilities_matches.matches)}. Report may be incomplete.")
            # Fallback to an empty dict if it's not the expected type to avoid rd.ResultDocument.from_capa error
            actual_matches_for_doc = {}
        else:
            actual_matches_for_doc = capabilities_matches.matches

        doc = rd.ResultDocument.from_capa(meta_for_report, loaded_rules, actual_matches_for_doc)
        
        # 11. Serialize to JSON string then parse back to dict to ensure clean Python dict
        # exclude_none=True is good for cleaner output
        json_output_str = doc.model_dump_json(exclude_none=True, indent=None) # No indent for compactness
        
        capa_results["results"] = json.loads(json_output_str)
        capa_results["status"] = "Analysis complete (adapted workflow)"
        logger.info("Capa analysis: Successfully generated ResultDocument and parsed to JSON.")

    # --- Capa Specific Exception Handling (from capa.exceptions) ---
    except (InvalidArgument, EmptyReportError, UnsupportedOSError, UnsupportedArchError, 
            UnsupportedFormatError, UnsupportedRuntimeError) as e_capa_specific_api:
        error_msg = f"Capa analysis failed with a capa-specific API exception: {type(e_capa_specific_api).__name__} - {str(e_capa_specific_api)}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (Capa API specific)"
        capa_results["error"] = error_msg
    # --- Custom Local CapaError Handling ---
    except (InvalidRule, RulesAccessError, FreezingError) as e_local_capa_handling:
        error_msg = f"Capa analysis failed due to local handling issue: {type(e_local_capa_handling).__name__} - {str(e_local_capa_handling)}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (Local Capa Handling)"
        capa_results["error"] = error_msg
    # --- General Exception Handling ---
    except AttributeError as e_attr: # Often indicates API incompatibility
        error_msg = f"Capa API call failed (AttributeError): {e_attr}. This may indicate an API incompatibility or a missing component in the installed capa version. Check capa version and dependencies."
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (API incompatibility/AttributeError)"
        capa_results["error"] = error_msg
    except FileNotFoundError as e_fnf: # If capa itself can't find a file it needs (e.g. during extraction)
        error_msg = f"Capa analysis failed (FileNotFoundError by capa): {e_fnf}."
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (File Not Found for capa)"
        capa_results["error"] = error_msg
    except Exception as e_generic_capa_run:
        # Check for capa's ShouldExitError if it's defined (older capa versions might not have it)
        should_exit_error_type = getattr(capa.main, 'ShouldExitError', None)
        if should_exit_error_type and isinstance(e_generic_capa_run, should_exit_error_type):
            error_msg = f"Capa analysis aborted by capa's internal exit request ({type(e_generic_capa_run).__name__}): {e_generic_capa_run} (status_code: {getattr(e_generic_capa_run, 'status_code', 'N/A')})"
            capa_results["status"] = f"Error during analysis (Capa ShouldExitError: {type(e_generic_capa_run).__name__})"
        else:
            error_msg = f"Unexpected error during adapted capa analysis execution: {type(e_generic_capa_run).__name__} - {e_generic_capa_run}"
            capa_results["status"] = "Unexpected error during capa execution"
        logger.error(error_msg, exc_info=verbose)
        capa_results["error"] = error_msg

    return capa_results

# --- String Utilities ---
def _extract_strings_from_data(data_bytes: bytes, min_length: int = 5) -> List[Tuple[int, str]]:
    """
    Extracts printable ASCII strings from a byte sequence.
    A string is a sequence of printable ASCII characters (space to '~').

    Args:
        data_bytes: The byte sequence to extract strings from.
        min_length: The minimum length for a sequence to be considered a string.

    Returns:
        A list of tuples, where each tuple is (offset, string_value).
    """
    strings_found: List[Tuple[int, str]] = []
    current_string_chars: List[str] = []
    current_offset: int = -1

    for i, byte_val in enumerate(data_bytes):
        char_val = chr(byte_val) # Convert byte to character
        # Check if the character is printable ASCII (space to tilde)
        if ' ' <= char_val <= '~':
            if not current_string_chars: # Start of a new potential string
                current_offset = i
            current_string_chars.append(char_val)
        else: # Non-printable character, or end of data
            if len(current_string_chars) >= min_length:
                strings_found.append((current_offset, "".join(current_string_chars)))
            current_string_chars = [] # Reset for next potential string
            current_offset = -1
            
    # Check for any string at the very end of the data
    if len(current_string_chars) >= min_length and current_offset != -1:
        strings_found.append((current_offset, "".join(current_string_chars)))
        
    return strings_found


def _search_specific_strings_in_data(data_bytes: bytes, search_terms: List[str]) -> Dict[str, List[int]]:
    """
    Searches for occurrences of specific ASCII strings within a byte sequence.
    Search is case-sensitive.

    Args:
        data_bytes: The byte sequence to search within.
        search_terms: A list of ASCII strings to search for.

    Returns:
        A dictionary where keys are the search terms and values are lists of
        integer offsets where each term was found.
    """
    results: Dict[str, List[int]] = {term: [] for term in search_terms}
    for term in search_terms:
        try:
            # Encode search term to bytes, assuming ASCII or compatible (e.g., UTF-8 if term has non-ASCII)
            # For pure ASCII search, 'ascii' is stricter. 'utf-8' is more flexible if terms might be non-ASCII.
            term_bytes = term.encode('ascii', 'ignore') # Ignore non-ASCII chars in search term
        except UnicodeEncodeError:
            logger.warning(f"String search: Could not encode search term '{term}' to ASCII. Skipping this term.")
            continue # Skip terms that cannot be ASCII encoded

        current_search_offset = 0
        while True:
            found_at_index = data_bytes.find(term_bytes, current_search_offset)
            if found_at_index == -1: # Not found
                break
            results[term].append(found_at_index)
            current_search_offset = found_at_index + 1 # Continue search from after the found instance
            
    return results


def _format_hex_dump_lines(data_chunk: bytes, start_address: int = 0, bytes_per_line: int = 16) -> List[str]:
    """
    Formats a chunk of byte data into a list of hex dump string lines.

    Args:
        data_chunk: The byte data to dump.
        start_address: The starting address for the dump (for display purposes).
        bytes_per_line: Number of bytes to display per line.

    Returns:
        A list of formatted hex dump lines.
    """
    lines: List[str] = []
    if bytes_per_line <= 0: bytes_per_line = 16 # Ensure positive bytes_per_line

    for i in range(0, len(data_chunk), bytes_per_line):
        chunk_current_line = data_chunk[i : i + bytes_per_line]
        
        # Format hex part (e.g., "00 01 02 ... FF")
        hex_part = ' '.join(f"{b:02x}" for b in chunk_current_line)
        # Pad hex part to align ASCII part, considering spaces between bytes
        hex_part_padded = hex_part.ljust(bytes_per_line * 3 - 1) 

        # Format ASCII part (printable chars or '.')
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk_current_line)
        
        # Combine into a line: Address  Hex Bytes  |ASCII Chars|
        lines.append(f"{start_address + i:08x}  {hex_part_padded}  |{ascii_part}|")
        
    return lines


# --- Refactored PE Parsing Helper Functions ---
# These functions take a pefile.PE object and extract specific information into dictionaries or lists.

def _parse_file_hashes(data: bytes) -> Dict[str, Optional[str]]:
    """Calculates MD5, SHA1, SHA256, and ssdeep hashes for the given data."""
    hashes: Dict[str, Optional[str]] = {"md5": None, "sha1": None, "sha256": None, "ssdeep": None}
    try:
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
        try:
            hashes["ssdeep"] = ssdeep_hasher.hash(data) # Use the global ssdeep_hasher instance
        except Exception as e_ssdeep:
            logger.warning(f"SSDeep hash calculation error: {e_ssdeep}")
            hashes["ssdeep"] = f"Error calculating ssdeep: {e_ssdeep}"
    except Exception as e_hash_general: # Catch any other hashing error
        logger.warning(f"General file hash calculation error: {e_hash_general}")
        # Mark all as error if a general failure occurs, or handle individually
        for k in ["md5","sha1","sha256"]: hashes[k] = f"Error: {e_hash_general}"
    return hashes

def _parse_dos_header(pe: pefile.PE) -> Dict[str, Any]:
    """Parses the DOS_HEADER, returning its dictionary representation or an error."""
    if hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER:
        # pe.DOS_HEADER.dump_dict() returns a dictionary where keys are field names
        # and values are dictionaries like {'Value': ..., 'Offset': ..., 'FileOffset': ...}
        # We are primarily interested in the 'Value' part for the actual data.
        dos_header_dump = pe.DOS_HEADER.dump_dict()
        # Simplify: return the 'Value' sub-dictionary for each field if that's the primary interest,
        # or return the full dump_dict structure. The original script seemed to imply direct field access.
        # For consistency with other parsers, let's keep the full structure from dump_dict().
        return dos_header_dump # This returns the rich dict with Value, Offset etc.
    return {"error": "DOS Header not found or malformed in pefile object."}


def _parse_nt_headers(pe: pefile.PE) -> Tuple[Dict[str, Any], str]:
    """Parses NT_HEADERS (Signature, FileHeader, OptionalHeader), returning info and PE type string."""
    nt_headers_info: Dict[str, Any] = {}
    magic_type_str = "Unknown PE Type" # Default

    if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS:
        nt_headers_info['signature_raw_value'] = getattr(pe.NT_HEADERS, 'Signature', None)
        nt_headers_info['signature_hex'] = hex(nt_headers_info['signature_raw_value']) if nt_headers_info['signature_raw_value'] is not None else "N/A"

        if hasattr(pe.NT_HEADERS, 'FILE_HEADER') and pe.NT_HEADERS.FILE_HEADER:
            fh_obj = pe.NT_HEADERS.FILE_HEADER
            fh_dict = fh_obj.dump_dict() # Rich dict with Value, Offset for each field
            # Add interpreted fields directly to our output for fh_dict
            fh_dict['characteristics_interpreted'] = get_file_characteristics(fh_obj.Characteristics)
            fh_dict['TimeDateStamp_iso_utc'] = format_timestamp(fh_obj.TimeDateStamp)
            nt_headers_info['file_header'] = fh_dict
        else:
            nt_headers_info['file_header'] = {"error": "File Header (IMAGE_FILE_HEADER) not found within NT_HEADERS."}

        if hasattr(pe.NT_HEADERS, 'OPTIONAL_HEADER') and pe.NT_HEADERS.OPTIONAL_HEADER:
            oh_obj = pe.NT_HEADERS.OPTIONAL_HEADER
            oh_dict = oh_obj.dump_dict() # Rich dict
            # Add interpreted fields
            oh_dict['dll_characteristics_interpreted'] = get_dll_characteristics(oh_obj.DllCharacteristics)
            
            magic_val = oh_obj.Magic
            if magic_val == pefile.OPTIONAL_HEADER_MAGIC_PE: # 0x10b
                magic_type_str = "PE32 (32-bit executable)"
            elif magic_val == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS: # 0x20b
                magic_type_str = "PE32+ (64-bit executable)"
            else:
                magic_type_str = f"Unknown Magic Value ({hex(magic_val)})"
            oh_dict['pe_architecture_type_string'] = magic_type_str
            nt_headers_info['optional_header'] = oh_dict
        else:
            nt_headers_info['optional_header'] = {"error": "Optional Header (IMAGE_OPTIONAL_HEADER) not found within NT_HEADERS."}
    else:
        nt_headers_info = {"error": "NT Headers (IMAGE_NT_HEADERS) structure not found in pefile object."}
        
    return nt_headers_info, magic_type_str


def _parse_data_directories(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses all data directories, returning a list of their info including names."""
    data_dirs_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and \
       isinstance(pe.OPTIONAL_HEADER.DATA_DIRECTORY, list):
        for i, dir_entry_obj in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            # dir_entry_obj is a DataDirEntry object from pefile
            entry_info = dir_entry_obj.dump_dict() # Rich dict with Value, Offset
            entry_info['directory_name'] = dir_entry_obj.name # From pefile's mapping
            entry_info['directory_index'] = i
            data_dirs_list.append(entry_info)
    else:
        # This case should be rare if OptionalHeader exists, but good to have a note.
        logger.debug("_parse_data_directories: No OPTIONAL_HEADER or DATA_DIRECTORY list found.")
    return data_dirs_list


def _parse_sections(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses all sections, including names, characteristics, entropy, and hashes."""
    sections_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'sections') and isinstance(pe.sections, list):
        for section_obj in pe.sections: # section_obj is a SectionStructure instance
            sec_dict = section_obj.dump_dict() # Rich dict for the section header fields
            
            # Add interpreted/calculated fields
            try:
                sec_dict['name_decoded'] = section_obj.Name.decode('utf-8', 'ignore').rstrip('\x00')
            except Exception as e_name_decode:
                sec_dict['name_decoded'] = f"<Error decoding name: {e_name_decode}>"
                logger.warning(f"Error decoding section name bytes '{section_obj.Name.hex()}': {e_name_decode}")

            sec_dict['characteristics_interpreted'] = get_section_characteristics(section_obj.Characteristics)
            sec_dict['entropy_calculated'] = section_obj.get_entropy() # pefile calculates this

            # Calculate hashes for the section data
            try:
                section_data = section_obj.get_data()
                sec_dict['data_md5'] = hashlib.md5(section_data).hexdigest()
                sec_dict['data_sha1'] = hashlib.sha1(section_data).hexdigest()
                sec_dict['data_sha256'] = hashlib.sha256(section_data).hexdigest()
                try:
                    sec_dict['data_ssdeep'] = ssdeep_hasher.hash(section_data)
                except Exception as e_s_ssdeep:
                    sec_dict['data_ssdeep'] = f"Error: {e_s_ssdeep}"
                    logger.warning(f"SSDeep hash error for section '{sec_dict['name_decoded']}': {e_s_ssdeep}")
            except Exception as e_sec_data:
                logger.warning(f"Could not get data or hash section '{sec_dict.get('name_decoded', 'UnknownSection')}': {e_sec_data}")
                for h_key in ['data_md5', 'data_sha1', 'data_sha256', 'data_ssdeep']:
                    sec_dict[h_key] = f"Error getting section data: {e_sec_data}"
            
            sections_list.append(sec_dict)
    return sections_list

def _parse_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses the import table, detailing imported DLLs and symbols."""
    imports_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and isinstance(pe.DIRECTORY_ENTRY_IMPORT, list):
        for import_entry_obj in pe.DIRECTORY_ENTRY_IMPORT: # import_entry_obj is an ImportDescData instance
            dll_info: Dict[str, Any] = {'dll_name': "Unknown DLL"}
            try:
                # import_entry_obj.dll is bytes, needs decoding
                dll_info['dll_name'] = import_entry_obj.dll.decode('utf-8', 'ignore') if import_entry_obj.dll else "N/A (No DLL Name)"
            except Exception as e_dll_name:
                dll_info['dll_name'] = f"<Error decoding DLL name: {e_dll_name}>"
                logger.warning(f"Error decoding import DLL name bytes '{import_entry_obj.dll.hex() if import_entry_obj.dll else b''}': {e_dll_name}")

            # The ImportDescData.struct is the IMAGE_IMPORT_DESCRIPTOR structure
            dll_info['import_descriptor_struct'] = import_entry_obj.struct.dump_dict() if hasattr(import_entry_obj, 'struct') else {"error": "Descriptor struct not found"}
            
            dll_info['imported_symbols'] = []
            if hasattr(import_entry_obj, 'imports') and isinstance(import_entry_obj.imports, list):
                for imp_symbol_obj in import_entry_obj.imports: # imp_symbol_obj is an ImportData instance
                    sym_info: Dict[str, Any] = {
                        'address_rva': hex(imp_symbol_obj.address) if imp_symbol_obj.address is not None else None,
                        'name_decoded': None,
                        'ordinal_number': imp_symbol_obj.ordinal,
                        'is_imported_by_ordinal': imp_symbol_obj.import_by_ordinal if hasattr(imp_symbol_obj, 'import_by_ordinal') else (imp_symbol_obj.name is None),
                        'bound_forwarder_rva': hex(imp_symbol_obj.bound) if imp_symbol_obj.bound is not None else None,
                        'hint_name_table_rva': hex(imp_symbol_obj.hint_name_table_rva) if hasattr(imp_symbol_obj, 'hint_name_table_rva') and imp_symbol_obj.hint_name_table_rva is not None else None,
                        # Direct struct dump if needed for all fields:
                        # 'raw_import_data_struct': imp_symbol_obj.struct.dump_dict() if hasattr(imp_symbol_obj, 'struct') else {}
                    }
                    if imp_symbol_obj.name:
                        try:
                            sym_info['name_decoded'] = imp_symbol_obj.name.decode('utf-8', 'ignore')
                        except Exception as e_sym_name:
                            sym_info['name_decoded'] = f"<Error decoding symbol name: {e_sym_name}>"
                            logger.warning(f"Error decoding import symbol name bytes '{imp_symbol_obj.name.hex()}': {e_sym_name} for DLL {dll_info['dll_name']}")
                    else: # If imported by ordinal, name is None
                        sym_info['name_decoded'] = "N/A (Imported by Ordinal)"
                    
                    dll_info['imported_symbols'].append(sym_info)
            imports_list.append(dll_info)
    return imports_list


def _parse_exports(pe: pefile.PE) -> Dict[str, Any]:
    """Parses the export table, including the DLL name and exported symbols."""
    exports_info: Dict[str, Any] = {"error": "Export table not found or not parsed by pefile."}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
        export_dir_obj = pe.DIRECTORY_ENTRY_EXPORT # This is an ExportDirData instance
        exports_info = {} # Reset, as we found the directory

        # The ExportDirData.struct is the IMAGE_EXPORT_DIRECTORY structure
        exports_info['export_directory_struct'] = export_dir_obj.struct.dump_dict() if hasattr(export_dir_obj, 'struct') else {"error": "Export directory struct not found"}
        
        try:
            # export_dir_obj.name is bytes
            exports_info['exported_dll_name'] = export_dir_obj.name.decode('utf-8', 'ignore') if export_dir_obj.name else "N/A (No Exported DLL Name)"
        except Exception as e_exp_name:
            exports_info['exported_dll_name'] = f"<Error decoding exported DLL name: {e_exp_name}>"
            logger.warning(f"Error decoding export DLL name bytes '{export_dir_obj.name.hex() if export_dir_obj.name else b''}': {e_exp_name}")

        exports_info['exported_symbols'] = []
        if hasattr(export_dir_obj, 'symbols') and isinstance(export_dir_obj.symbols, list):
            for exp_symbol_obj in export_dir_obj.symbols: # exp_symbol_obj is an ExportData instance
                sym_info: Dict[str, Any] = {
                    'address_rva': hex(exp_symbol_obj.address) if exp_symbol_obj.address is not None else None,
                    'name_decoded': None,
                    'ordinal_number': exp_symbol_obj.ordinal,
                    'forwarder_string': None
                    # 'raw_export_data_struct': exp_symbol_obj.struct.dump_dict() if hasattr(exp_symbol_obj, 'struct') else {}
                }
                if exp_symbol_obj.name:
                    try:
                        sym_info['name_decoded'] = exp_symbol_obj.name.decode('utf-8', 'ignore')
                    except Exception as e_exp_sym_name:
                        sym_info['name_decoded'] = f"<Error decoding symbol name: {e_exp_sym_name}>"
                        logger.warning(f"Error decoding export symbol name bytes '{exp_symbol_obj.name.hex()}': {e_exp_sym_name}")
                else: # Can be exported by ordinal without a name
                    sym_info['name_decoded'] = "N/A (Exported by Ordinal, No Name)"

                if exp_symbol_obj.forwarder:
                    try:
                        sym_info['forwarder_string'] = exp_symbol_obj.forwarder.decode('utf-8', 'ignore')
                    except Exception as e_fwd_str:
                        sym_info['forwarder_string'] = f"<Error decoding forwarder: {e_fwd_str}>"
                        logger.warning(f"Error decoding forwarder string bytes '{exp_symbol_obj.forwarder.hex()}': {e_fwd_str}")
                
                exports_info['exported_symbols'].append(sym_info)
    return exports_info


def _parse_resources_summary(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses a summary of resources, detailing type, ID/name, language, RVA, and size."""
    resources_summary_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') \
       and isinstance(pe.DIRECTORY_ENTRY_RESOURCE.entries, list):
        for res_type_entry_obj in pe.DIRECTORY_ENTRY_RESOURCE.entries: # ResourceDirEntryData for Type
            type_id_val = getattr(res_type_entry_obj, 'id', None)
            type_name_str = pefile.RESOURCE_TYPE.get(type_id_val, str(type_id_val)) # Predefined types or ID
            
            # If type entry has a name string (custom type)
            if hasattr(res_type_entry_obj, 'name') and res_type_entry_obj.name is not None:
                try:
                    # Name is a ResourceDirStringDataU object, access its string attribute
                    type_name_str = f"{res_type_entry_obj.name.string.decode('utf-16le', 'ignore')} (ID: {type_id_val if type_id_val is not None else 'N/A'})"
                except Exception as e_type_name:
                    type_name_str = f"<Error decoding type name: {e_type_name}> (ID: {type_id_val if type_id_val is not None else 'N/A'})"

            if hasattr(res_type_entry_obj, 'directory') and hasattr(res_type_entry_obj.directory, 'entries'):
                for res_id_entry_obj in res_type_entry_obj.directory.entries: # ResourceDirEntryData for ID/Name
                    id_val = getattr(res_id_entry_obj, 'id', None)
                    id_name_str = str(id_val) # Default to ID string

                    if hasattr(res_id_entry_obj, 'name') and res_id_entry_obj.name is not None:
                        try:
                            id_name_str = f"{res_id_entry_obj.name.string.decode('utf-16le', 'ignore')} (ID: {id_val if id_val is not None else 'N/A'})"
                        except Exception as e_id_name:
                             id_name_str = f"<Error decoding ID/name string: {e_id_name}> (ID: {id_val if id_val is not None else 'N/A'})"
                    elif id_val is not None: # If no name string, but has an ID
                        id_name_str = f"ID: {id_val}"
                    else: # No name string and no ID (should be rare)
                        id_name_str = "Unnamed/ID-less Resource"

                    if hasattr(res_id_entry_obj, 'directory') and hasattr(res_id_entry_obj.directory, 'entries'):
                        for res_lang_entry_obj in res_id_entry_obj.directory.entries: # ResourceDirEntryData for Language
                            lang_id_val = getattr(res_lang_entry_obj, 'id', 'N/A_Lang')
                            # The actual data entry is under res_lang_entry_obj.data
                            if hasattr(res_lang_entry_obj, 'data') and hasattr(res_lang_entry_obj.data, 'struct'):
                                data_struct_obj = res_lang_entry_obj.data.struct # This is ResourceDataEntryData
                                resources_summary_list.append({
                                    "resource_type": type_name_str,
                                    "resource_id_or_name": id_name_str,
                                    "language_id": lang_id_val,
                                    "language_sublanguage_str": pe.get_language_string_from_id(lang_id_val) if lang_id_val != 'N/A_Lang' else "N/A",
                                    "data_rva": hex(getattr(data_struct_obj, 'OffsetToData', 0)),
                                    "data_size_bytes": getattr(data_struct_obj, 'Size', 0),
                                    "codepage": getattr(data_struct_obj, 'CodePage', 0),
                                    # 'raw_resource_data_entry_struct': data_struct_obj.dump_dict()
                                })
    return resources_summary_list


def _parse_version_info(pe: pefile.PE) -> Dict[str, Any]:
    """Parses version information from RT_VERSION resource, if available."""
    ver_info: Dict[str, Any] = {"status": "Version info not found or not parsed."}
    
    vs_fixedfileinfo_list = []
    if hasattr(pe, 'VS_FIXEDFILEINFO') and isinstance(pe.VS_FIXEDFILEINFO, list) and pe.VS_FIXEDFILEINFO:
        # VS_FIXEDFILEINFO is a list, usually with one VS_FIXEDFILEINFOStructure
        for fixed_info_struct in pe.VS_FIXEDFILEINFO:
            if hasattr(fixed_info_struct, 'dump_dict'):
                fixed_dict = fixed_info_struct.dump_dict()
                # Add formatted version strings
                file_version_ms = getattr(fixed_info_struct, 'FileVersionMS', 0)
                file_version_ls = getattr(fixed_info_struct, 'FileVersionLS', 0)
                prod_version_ms = getattr(fixed_info_struct, 'ProductVersionMS', 0)
                prod_version_ls = getattr(fixed_info_struct, 'ProductVersionLS', 0)
                
                fixed_dict['file_version_formatted_str'] = (
                    f"{(file_version_ms >> 16)}."
                    f"{(file_version_ms & 0xFFFF)}."
                    f"{(file_version_ls >> 16)}."
                    f"{(file_version_ls & 0xFFFF)}"
                )
                fixed_dict['product_version_formatted_str'] = (
                    f"{(prod_version_ms >> 16)}."
                    f"{(prod_version_ms & 0xFFFF)}."
                    f"{(prod_version_ls >> 16)}."
                    f"{(prod_version_ls & 0xFFFF)}"
                )
                vs_fixedfileinfo_list.append(fixed_dict)
        if vs_fixedfileinfo_list:
            ver_info['vs_fixedfileinfo_entries'] = vs_fixedfileinfo_list
            ver_info["status"] = "VS_FIXEDFILEINFO parsed."

    stringfileinfo_blocks = []
    varfileinfo_blocks = []
    if hasattr(pe, 'FileInfo') and isinstance(pe.FileInfo, list) and pe.FileInfo:
        # pe.FileInfo is a list of FileInfoEntryData objects
        for fi_block_entry_obj in pe.FileInfo:
            block_detail: Dict[str, Any] = {}
            # Check if it's StringFileInfo or VarFileInfo
            if hasattr(fi_block_entry_obj, 'StringTable') and isinstance(fi_block_entry_obj.StringTable, list):
                # This entry is a StringFileInfo block, containing StringTable(s)
                block_detail['type'] = "StringFileInfo"
                string_tables_parsed = []
                for string_table_obj in fi_block_entry_obj.StringTable: # string_table_obj is a StringTable structure
                    st_entry_data: Dict[str, Any] = {
                        'lang_codepage_hex': string_table_obj.LangID.decode('utf-8','ignore') if hasattr(string_table_obj,'LangID') and string_table_obj.LangID else "N/A", # LangID is hex string "040904B0"
                        'string_key_value_pairs': {}
                    }
                    if hasattr(string_table_obj, 'entries') and isinstance(string_table_obj.entries, dict):
                        for key_bytes, val_bytes in string_table_obj.entries.items():
                            key_str = key_bytes.decode('utf-8', 'ignore') if isinstance(key_bytes, bytes) else str(key_bytes)
                            val_str = val_bytes.decode('utf-16le', 'ignore') if isinstance(val_bytes, bytes) else str(val_bytes) # Values often UTF-16LE
                            st_entry_data['string_key_value_pairs'][key_str] = val_str
                    string_tables_parsed.append(st_entry_data)
                block_detail['string_tables'] = string_tables_parsed
                stringfileinfo_blocks.append(block_detail)

            elif hasattr(fi_block_entry_obj, 'Var') and isinstance(fi_block_entry_obj.Var, list):
                # This entry is a VarFileInfo block, containing Var(s)
                block_detail['type'] = "VarFileInfo"
                vars_parsed = []
                for var_obj in fi_block_entry_obj.Var: # var_obj is a Var structure
                    var_key_str = var_obj.szKey.decode('utf-16le','ignore') if hasattr(var_obj,'szKey') and var_obj.szKey else "N/A"
                    # var_obj.Value is often a list of DWORDs (lang/charset pairs)
                    var_val_repr = []
                    if hasattr(var_obj, 'Value') and isinstance(var_obj.Value, list):
                        for i in range(0, len(var_obj.Value), 2): # Process in pairs
                            if i + 1 < len(var_obj.Value):
                                lang_id = var_obj.Value[i]
                                charset_id = var_obj.Value[i+1]
                                var_val_repr.append(f"LangID={hex(lang_id)}, CharsetID={hex(charset_id)}")
                            else: # Odd number of values?
                                var_val_repr.append(f"RawValue={hex(var_obj.Value[i])}")
                    elif hasattr(var_obj, 'Value'): # If not a list, show raw
                         var_val_repr = [str(var_obj.Value)]

                    vars_parsed.append({var_key_str: var_val_repr})
                block_detail['vars_translations'] = vars_parsed
                varfileinfo_blocks.append(block_detail)
        
        if stringfileinfo_blocks or varfileinfo_blocks:
             ver_info["status"] = "FileInfo blocks parsed." # Update status
        if stringfileinfo_blocks: ver_info['stringfileinfo_blocks'] = stringfileinfo_blocks
        if varfileinfo_blocks: ver_info['varfileinfo_blocks'] = varfileinfo_blocks
        
    if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe.VS_VERSIONINFO, 'Value') and pe.VS_VERSIONINFO.Value:
        # This is the 'VS_VERSION_INFO' key string itself, usually "VS_VERSION_INFO"
        ver_info['vs_versioninfo_struct_key_string'] = pe.VS_VERSIONINFO.Value.decode('ascii', 'ignore')

    return ver_info


def _parse_debug_info(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses debug directory entries, including type and PDB filename if present."""
    debug_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and isinstance(pe.DIRECTORY_ENTRY_DEBUG, list):
        for debug_entry_obj in pe.DIRECTORY_ENTRY_DEBUG: # debug_entry_obj is DebugData instance
            dbg_item: Dict[str, Any] = {}
            # debug_entry_obj.struct is IMAGE_DEBUG_DIRECTORY
            dbg_item['debug_directory_struct'] = debug_entry_obj.struct.dump_dict() if hasattr(debug_entry_obj, 'struct') else {"error": "Debug directory struct not found"}
            
            raw_type_val = getattr(debug_entry_obj.struct, 'Type', -1)
            dbg_item['type_string_interpreted'] = pefile.DEBUG_TYPE.get(raw_type_val, f"UNKNOWN_DEBUG_TYPE ({raw_type_val})")

            # The 'entry' attribute of DebugData depends on the Type.
            # For CodeView (PDB), it's often a CV_INFO_PDB70 or similar structure.
            if hasattr(debug_entry_obj, 'entry') and debug_entry_obj.entry:
                debug_entry_specifics: Dict[str, Any] = {}
                # Try to dump the specific entry struct if pefile parsed it
                if hasattr(debug_entry_obj.entry, 'dump_dict'):
                    debug_entry_specifics = debug_entry_obj.entry.dump_dict()
                
                # Specifically extract PDB filename for CodeView types
                if raw_type_val == pefile.DEBUG_TYPE.get('IMAGE_DEBUG_TYPE_CODEVIEW'):
                    pdb_filename_bytes = getattr(debug_entry_obj.entry, 'PdbFileName', None)
                    if pdb_filename_bytes and isinstance(pdb_filename_bytes, bytes):
                        try:
                            debug_entry_specifics['pdb_filename_decoded'] = pdb_filename_bytes.decode('utf-8', 'ignore').rstrip('\x00')
                        except Exception as e_pdb_name:
                            debug_entry_specifics['pdb_filename_decoded'] = f"<Error decoding PDB name: {e_pdb_name}>"
                            logger.warning(f"Error decoding PDB filename bytes '{pdb_filename_bytes.hex()}': {e_pdb_name}")
                    elif pdb_filename_bytes: # If not bytes but exists
                         debug_entry_specifics['pdb_filename_raw'] = str(pdb_filename_bytes)


                # For other types, the 'entry' might just have raw fields.
                # Add any non-dump_dict attributes if dump_dict wasn't available or to supplement it.
                if not debug_entry_specifics and not hasattr(debug_entry_obj.entry, 'dump_dict'):
                    for attr_name in dir(debug_entry_obj.entry):
                        if not attr_name.startswith('_') and not callable(getattr(debug_entry_obj.entry, attr_name)):
                            attr_val = getattr(debug_entry_obj.entry, attr_name)
                            try: debug_entry_specifics[attr_name] = str(attr_val) # Simple string conversion
                            except: debug_entry_specifics[attr_name] = f"<Unrepresentable attribute {type(attr_val).__name__}>"
                
                if debug_entry_specifics:
                    dbg_item['debug_type_specific_entry_details'] = debug_entry_specifics
                else:
                    dbg_item['debug_type_specific_entry_details'] = {"info": "No further parsed details for this debug type by pefile."}
            
            debug_list.append(dbg_item)
    return debug_list

def _parse_digital_signature(pe: pefile.PE, filepath: str, # Filepath for context, not directly used by pefile for this
                             cryptography_available_flag: bool,
                             signify_available_flag: bool) -> Dict[str, Any]:
    """
    Parses digital signature information from the security directory.
    Uses 'cryptography' for certificate parsing and 'signify' for Authenticode validation if available.
    """
    sig_info: Dict[str, Any] = {"status": "Digital signature information not found or not parsed."}

    sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    if hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and \
       len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:

        sec_dir_entry_obj = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx] # DataDirEntry object
        sig_rva = sec_dir_entry_obj.VirtualAddress # This is RVA for PE, but File Offset for actual signature data
        sig_size = sec_dir_entry_obj.Size

        sig_info['security_directory_details'] = {
            'virtual_address_rva': hex(sig_rva),
            'size_bytes': sig_size,
            'raw_struct': sec_dir_entry_obj.dump_dict()
        }

        if sig_rva != 0 and sig_size != 0:
            sig_info['status'] = "Embedded signature data present in security directory."
            sig_info['is_signed_according_to_directory'] = True

            # The actual signature data is at a file offset, not RVA.
            # pefile's get_data() uses RVA, but for IMAGE_DIRECTORY_ENTRY_SECURITY,
            # VirtualAddress is actually a File Offset to the WIN_CERTIFICATE structure.
            # However, pefile handles this internally if you try to access signature data.
            # The raw signature block can be obtained, but parsing it is complex.

            # Status of 'cryptography' library usage
            if cryptography_available_flag:
                # signify internally uses the 'cryptography' library for parsing certificates
                # when it processes Authenticode signatures. So, if signify is used,
                # cryptography's capabilities are inherently leveraged.
                sig_info['cryptography_parsing_status'] = ("'cryptography' library is available. "
                                                           "It is used by 'signify' for certificate parsing within Authenticode structures.")
            else:
                sig_info['cryptography_parsing_status'] = ("'cryptography' library not available. "
                                                           "Full digital signature parsing via 'signify' might be limited or unavailable.")

            # Using 'signify' for Authenticode validation
            if signify_available_flag:
                signify_validation_results = []
                try:
                    # signify works with the file path or a file-like object of the PE data
                    with open(filepath, 'rb') as f_pe_for_signify: # Open the original file for signify
                        # Dynamically import AuthenticodeVerificationResult and SignedPEFile from signify.authenticode
                        # This ensures they are only accessed if signify_available_flag is True.
                        from signify.authenticode import AuthenticodeVerificationResult, SignedPEFile

                        signed_pe_file_obj = SignedPEFile(f_pe_for_signify) # from signify.authenticode

                        if not signed_pe_file_obj.signed_datas: # signed_datas is a list of AuthenticodeSignedData
                            signify_validation_results.append({
                                "status_message": "Signify: No Authenticode signature blocks found in the file.",
                                "is_valid_overall": False
                            })
                        else:
                            for i, signed_data_obj in enumerate(signed_pe_file_obj.signed_datas):
                                # signed_data_obj is an AuthenticodeSignedData instance
                                verification_result_enum, verification_exception = signed_data_obj.explain_verify()
                                # verification_result_enum is AuthenticodeVerificationResult

                                current_block_result: Dict[str, Any] = {
                                    "signature_block_index": i + 1,
                                    "verification_status_code": verification_result_enum.name, # e.g., OK, INVALID_HASH, UNTRUSTED_ROOT
                                    "verification_status_description": str(verification_result_enum), # Human-readable
                                    "is_considered_valid_by_signify": verification_result_enum == AuthenticodeVerificationResult.OK,
                                    "verification_exception_details": str(verification_exception) if verification_exception else None,
                                    "signer_info": None,
                                    "certificates_chain": [] # Placeholder for cert chain details
                                }

                                if signed_data_obj.signer_info:
                                    si = signed_data_obj.signer_info # SignerInfo object
                                    current_block_result["signer_info"] = {
                                        "program_name": getattr(si, 'program_name', None),
                                        "program_url": getattr(si, 'program_url', None), # Less common
                                        # IssuerAndSerialNumber or SignerIdentifier
                                        "issuer_dn_rfc4514": str(si.issuer.rfc4514_string()) if hasattr(si, 'issuer') and si.issuer else "N/A",
                                        "serial_number_hex": si.serial_number.hex() if hasattr(si, 'serial_number') and si.serial_number is not None else "N/A",
                                    }
                                    if si.countersigner and hasattr(si.countersigner, 'signing_time') and si.countersigner.signing_time:
                                        current_block_result["signer_info"]["timestamp_utc"] = si.countersigner.signing_time.isoformat()
                                    else:
                                         current_block_result["signer_info"]["timestamp_utc"] = "Not available or not timestamped"

                                # Extract certificate chain info from signed_data_obj.certificates (list of x509.Certificate)
                                if hasattr(signed_data_obj, 'certificates') and isinstance(signed_data_obj.certificates, list):
                                    for cert_idx, cert_obj in enumerate(signed_data_obj.certificates):
                                        current_block_result["certificates_chain"].append({
                                            "chain_index": cert_idx,
                                            "subject_dn_rfc4514": str(cert_obj.subject.rfc4514_string()),
                                            "issuer_dn_rfc4514": str(cert_obj.issuer.rfc4514_string()),
                                            "serial_number_hex": cert_obj.serial_number.hex(),
                                            "not_valid_before_utc": cert_obj.not_valid_before_utc.isoformat(),
                                            "not_valid_after_utc": cert_obj.not_valid_after_utc.isoformat(),
                                            "version": str(cert_obj.version),
                                        })
                                signify_validation_results.append(current_block_result)
                    sig_info['signify_authenticode_validation'] = signify_validation_results
                except ImportError: # Handle if signify.authenticode components can't be imported (should be caught by SIGNIFY_AVAILABLE)
                     sig_info['signify_authenticode_validation_error'] = "Signify library components (AuthenticodeVerificationResult, SignedPEFile) could not be imported. Ensure 'signify' is correctly installed."
                     logger.error(f"Signify import error for '{filepath}' though SIGNIFY_AVAILABLE was True.", exc_info=True)
                except Exception as e_signify:
                    sig_info['signify_authenticode_validation_error'] = f"Signify library error: {e_signify}"
                    logger.error(f"Signify validation error for '{filepath}': {e_signify}", exc_info=True) # Use exc_info for full traceback
            else:
                sig_info['signify_authenticode_validation_status'] = "Signify library not available."
        else: # sig_rva == 0 or sig_size == 0
            sig_info['status'] = "Security directory is empty or points to null; file is likely not signed directly."
            sig_info['is_signed_according_to_directory'] = False
    else: # No security directory entry in Optional Header
        sig_info['status'] = "Security directory not present in Optional Header; file is likely not signed directly."
        sig_info['is_signed_according_to_directory'] = False

    return sig_info

def _perform_peid_scan(pe: pefile.PE, 
                       peid_db_path_str: Optional[str], # Resolved path to DB
                       verbose: bool, 
                       skip_full_file_scan: bool, 
                       scan_all_sigs_heuristically_in_full_scan: bool
                       ) -> Dict[str, Any]:
    """
    Performs PEiD-like signature scanning using a custom database.
    Scans entry point and optionally the entire file (or specified sections).
    """
    peid_results: Dict[str, Any] = {
        "status": "PEiD scan not performed yet.",
        "database_path_used": peid_db_path_str,
        "ep_only_matches": [],      # Matches from signatures marked ep_only=true, at actual EP
        "heuristic_matches": [],    # Matches from any signature, found anywhere in scanned sections
        "errors": []
    }

    if not peid_db_path_str:
        logger.error("PEiD scan: Database path was not provided or resolved. Cannot perform PEiD scan.")
        peid_results["status"] = "PEiD DB path missing."
        peid_results["errors"].append("Database path not available.")
        return peid_results

    # Ensure the database file exists (it might be downloaded by ensure_peid_db_exists if called earlier)
    if not Path(peid_db_path_str).is_file():
        # Attempt to ensure/download it again if primary logic missed it or if called standalone
        if not ensure_peid_db_exists(PEID_USERDB_URL, peid_db_path_str, verbose):
            peid_results["status"] = f"PEiD DB '{peid_db_path_str}' not found and download failed."
            peid_results["errors"].append(peid_results["status"])
            return peid_results
            
    custom_signatures = parse_signature_file(peid_db_path_str, verbose)
    if not custom_signatures:
        peid_results["status"] = f"No PEiD signatures loaded from '{peid_db_path_str}' (file might be empty, malformed, or unreadable)."
        peid_results["errors"].append(peid_results["status"])
        return peid_results

    peid_results["status"] = "Scan performed." # Update status as we are proceeding

    # --- Entry Point Scan ---
    # Only scan EP if AddressOfEntryPoint is valid and non-zero
    ep_rva = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0)
    if ep_rva != 0:
        try:
            # Get section containing the entry point
            ep_section = pe.get_section_by_rva(ep_rva)
            if ep_section:
                ep_offset_in_section = ep_rva - ep_section.VirtualAddress
                # Read a chunk of data from EP (e.g., 2KB, common for packers)
                # Ensure read length doesn't exceed section data bounds from EP
                ep_data_chunk_len = min(2048, ep_section.SizeOfRawData - ep_offset_in_section)
                if ep_data_chunk_len > 0 :
                    ep_data_to_scan = ep_section.get_data(ep_offset_in_section, ep_data_chunk_len)
                    
                    ep_matches_found: Set[str] = set() # Use set to store unique signature names
                    for sig_dict in custom_signatures:
                        # For EP scan, we can consider all signatures, or only ep_only=true ones.
                        # Standard PEiD behavior is often to match any signature at EP.
                        # If sig_dict['ep_only'] is True, it *must* match at EP.
                        # If sig_dict['ep_only'] is False, it *can* match at EP or elsewhere.
                        # Here, we scan all sigs at EP.
                        match_name = find_pattern_in_data_regex(ep_data_to_scan, sig_dict, verbose, "Entry Point Area")
                        if match_name:
                            ep_matches_found.add(match_name)
                    peid_results["ep_only_matches"] = sorted(list(ep_matches_found)) # Store sorted list
                else:
                    logger.debug("PEiD EP Scan: Calculated EP data chunk length is zero or negative.")
            else:
                logger.warning(f"PEiD EP Scan: Could not find section for Entry Point RVA {hex(ep_rva)}.")
                peid_results["errors"].append(f"Section for EP RVA {hex(ep_rva)} not found.")
        except Exception as e_ep_scan:
            logger.warning(f"PEiD EP scan error: {e_ep_scan}", exc_info=verbose)
            peid_results["errors"].append(f"Error during EP scan: {e_ep_scan}")
    else: # ep_rva is 0
        logger.info("PEiD EP Scan: AddressOfEntryPoint is 0. Skipping entry point specific scan.")
        peid_results["ep_scan_status_note"] = "Skipped (AddressOfEntryPoint is 0)."


    # --- Full File / Heuristic Scan (if not skipped) ---
    if not skip_full_file_scan:
        heuristic_matches_found: Set[str] = set()
        
        # Determine sections to scan: typically executable sections, or first section as fallback
        sections_to_scan_heuristically = [s for s in pe.sections if hasattr(s, 'Characteristics') and 
                                          bool(s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])]
        if not sections_to_scan_heuristically and pe.sections: # Fallback to first section if no executable ones
            logger.info("PEiD Heuristic Scan: No executable sections found, scanning first section as fallback.")
            sections_to_scan_heuristically = [pe.sections[0]]
        elif not pe.sections:
             logger.warning("PEiD Heuristic Scan: No sections found in PE file. Cannot perform heuristic scan.")
             peid_results["errors"].append("No sections available for heuristic scan.")


        scan_tasks_args_for_threads = [] # List of (data, sig_dict, verbose, section_name)
        for section_obj_to_scan in sections_to_scan_heuristically:
            try:
                section_name_str = section_obj_to_scan.Name.decode('utf-8','ignore').rstrip('\x00')
                section_data_to_scan = section_obj_to_scan.get_data()
                if not section_data_to_scan: # Skip if section data is empty
                    logger.debug(f"PEiD Heuristic Scan: Section '{section_name_str}' is empty, skipping.")
                    continue

                for sig_dict_heuristic in custom_signatures:
                    # If scan_all_sigs_heuristically_in_full_scan is True, all sigs are used.
                    # Otherwise, only sigs not marked as ep_only=true are used for heuristic scan.
                    if scan_all_sigs_heuristically_in_full_scan or not sig_dict_heuristic['ep_only']:
                        scan_tasks_args_for_threads.append(
                            (section_data_to_scan, sig_dict_heuristic, verbose, section_name_str)
                        )
            except Exception as e_sec_prep:
                section_name_for_log_err = "UnknownSection"
                try: section_name_for_log_err = section_obj_to_scan.Name.decode('utf-8','ignore').rstrip('\x00')
                except: pass
                logger.warning(f"PEiD Heuristic Scan: Error preparing section '{section_name_for_log_err}': {e_sec_prep}")
                peid_results["errors"].append(f"Error preparing section '{section_name_for_log_err}' for heuristic scan: {e_sec_prep}")

        if scan_tasks_args_for_threads:
            # Use ThreadPoolExecutor for concurrent scanning of sections/signatures
            # Adjust max_workers as needed; os.cpu_count() is a common choice.
            num_workers = min(os.cpu_count() or 1, len(scan_tasks_args_for_threads)) # Avoid too many workers for few tasks
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                # map() might be simpler if find_pattern_in_data_regex takes args directly
                # submit() gives Future objects, allowing as_completed
                future_to_sig_name = {
                    executor.submit(find_pattern_in_data_regex, args_tuple[0], args_tuple[1], args_tuple[2], args_tuple[3]): args_tuple[1]['name']
                    for args_tuple in scan_tasks_args_for_threads
                }
                for future in concurrent.futures.as_completed(future_to_sig_name):
                    # sig_name_assoc = future_to_sig_name[future] # Get associated signature name
                    try:
                        match_result_name = future.result() # This is the signature name if matched
                        if match_result_name:
                            heuristic_matches_found.add(match_result_name)
                    except Exception as e_thread_scan:
                        # Log error from a specific scan thread
                        logger.warning(f"PEiD Heuristic Scan: Error in a scan thread: {e_thread_scan}", exc_info=verbose)
                        peid_results["errors"].append(f"Error in heuristic scan thread: {e_thread_scan}")
            
        peid_results["heuristic_matches"] = sorted(list(heuristic_matches_found))
    else: # skip_full_file_scan was True
        peid_results["heuristic_scan_status_note"] = "Skipped by user request (skip_full_peid_scan=True)."

    return peid_results


def _parse_rich_header(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    """Parses the Rich Header if present, decoding CompIDs and counts."""
    if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
        rich_header_obj = pe.RICH_HEADER # RichHeader object from pefile
        decoded_comp_id_entries: List[Dict[str, Any]] = []
        
        # rich_header_obj.values is a list of DWORDs (CompID, Count pairs)
        raw_compid_values = list(rich_header_obj.values) if rich_header_obj.values else []
        
        for i in range(0, len(raw_compid_values), 2): # Iterate in pairs
            if i + 1 < len(raw_compid_values):
                comp_id_dword = raw_compid_values[i]
                count_val = raw_compid_values[i+1]
                
                # Decode CompID: ProductID (high word), BuildNumber (low word)
                product_id = comp_id_dword >> 16
                build_number = comp_id_dword & 0xFFFF
                
                decoded_comp_id_entries.append({
                    "raw_comp_id_dword": hex(comp_id_dword),
                    "product_id_decoded_hex": hex(product_id),
                    "product_id_decoded_decimal": product_id,
                    "build_number_decoded": build_number,
                    "occurrence_count": count_val
                })
        
        return {
            'xor_key_hex': rich_header_obj.key.hex() if isinstance(rich_header_obj.key, bytes) else str(rich_header_obj.key),
            'checksum_from_header_struct': hex(rich_header_obj.checksum) if rich_header_obj.checksum is not None else None,
            'raw_compid_count_values_list': raw_compid_values, # The list of alternating CompIDs and counts
            'decoded_compid_entries': decoded_comp_id_entries,
            'raw_rich_header_data_hex': rich_header_obj.raw_data.hex() if rich_header_obj.raw_data else None,
            'decrypted_rich_header_data_hex': rich_header_obj.clear_data.hex() if rich_header_obj.clear_data else None
        }
    return None # No Rich Header found


def _parse_delay_load_imports(pe: pefile.PE, magic_type_str: str) -> List[Dict[str, Any]]:
    """Parses delay-load import directory, if present."""
    # Constants for ordinal flags (from winnt.h, often used by loaders)
    # For PE32 (32-bit), the high bit of the RVA/ordinal field is set if it's an ordinal.
    # For PE32+ (64-bit), the high bit of the QWORD RVA/ordinal field is set.
    IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
    IMAGE_ORDINAL_FLAG32 = 0x80000000

    delay_imports_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT') and isinstance(pe.DIRECTORY_ENTRY_DELAY_IMPORT, list):
        for delay_entry_obj in pe.DIRECTORY_ENTRY_DELAY_IMPORT: # delay_entry_obj is an ImportDescData instance
            delay_dll_info: Dict[str, Any] = {"delay_loaded_dll_name": "Unknown DelayLoad DLL"}
            
            # The ImgDelayDescr.szName is an RVA to the DLL name string
            if hasattr(delay_entry_obj.struct, 'szName') and delay_entry_obj.struct.szName != 0:
                try:
                    dll_name_str_bytes = pe.get_string_at_rva(delay_entry_obj.struct.szName)
                    delay_dll_info['delay_loaded_dll_name'] = dll_name_str_bytes.decode('ascii', 'ignore') if dll_name_str_bytes else "N/A (Name RVA points to empty string)"
                except Exception as e_dll_name_delay:
                    delay_dll_info['delay_loaded_dll_name'] = f"<Error decoding DelayLoad DLL name from RVA {hex(delay_entry_obj.struct.szName)}: {e_dll_name_delay}>"
                    logger.warning(f"Error decoding DelayLoad DLL name from RVA {hex(delay_entry_obj.struct.szName)}: {e_dll_name_delay}")
            
            delay_dll_info['delay_import_descriptor_struct'] = delay_entry_obj.struct.dump_dict() if hasattr(delay_entry_obj, 'struct') else {"error": "Delay import descriptor struct not found"}
            
            delay_dll_info['imported_symbols_via_delay_load'] = []
            
            # The ImgDelayDescr.pINT (Import Name Table) points to an array of RVAs/ordinals
            # This is similar to the regular import table's IAT/INT.
            if hasattr(delay_entry_obj.struct, 'pINT') and delay_entry_obj.struct.pINT != 0 and \
               hasattr(pe, 'OPTIONAL_HEADER'): # Need OPTIONAL_HEADER for ImageBase and pointer size
                
                thunk_array_rva = delay_entry_obj.struct.pINT
                ptr_size_bytes = 8 if magic_type_str.startswith("PE32+") else 4
                ordinal_flag = IMAGE_ORDINAL_FLAG64 if ptr_size_bytes == 8 else IMAGE_ORDINAL_FLAG32
                max_delay_symbols_to_parse = 2048 # Safety limit

                for i in range(max_delay_symbols_to_parse):
                    current_thunk_rva = thunk_array_rva + (i * ptr_size_bytes)
                    try:
                        thunk_value_raw = 0
                        if ptr_size_bytes == 8:
                            thunk_value_raw = pe.get_qword_at_rva(current_thunk_rva)
                        else: # ptr_size_bytes == 4
                            thunk_value_raw = pe.get_dword_at_rva(current_thunk_rva)
                        
                        if thunk_value_raw == 0: # End of the thunk array
                            break 

                        sym_name_delay: Optional[str] = None
                        sym_ordinal_delay: Optional[int] = None
                        
                        if thunk_value_raw & ordinal_flag: # Import by ordinal
                            sym_ordinal_delay = thunk_value_raw & 0xFFFF # Ordinal is in the lower 16 bits
                        else: # Import by name
                            # thunk_value_raw is an RVA to an IMAGE_IMPORT_BY_NAME structure
                            name_struct_rva = thunk_value_raw
                            try:
                                # IMAGE_IMPORT_BY_NAME has Hint (WORD) then Name (NULL-terminated string)
                                # pefile's get_string_at_rva handles this structure if it's simple enough,
                                # or we can parse manually. get_string_at_rva(name_struct_rva + 2) gets the name.
                                sym_name_bytes = pe.get_string_at_rva(name_struct_rva + 2) # Skip Hint field
                                sym_name_delay = sym_name_bytes.decode('ascii', 'ignore') if sym_name_bytes else "N/A (Name RVA points to empty string)"
                            except Exception as e_str_delay_sym:
                                logger.debug(f"Delay-load import symbol name fetch error at RVA {hex(name_struct_rva + 2)}: {e_str_delay_sym}")
                                sym_name_delay = f"<Error fetching name from RVA {hex(name_struct_rva + 2)}>"
                        
                        delay_dll_info['imported_symbols_via_delay_load'].append({
                            'name_decoded': sym_name_delay,
                            'ordinal_number': sym_ordinal_delay,
                            'thunk_rva_in_delay_int': hex(current_thunk_rva),
                            'raw_thunk_value': hex(thunk_value_raw)
                        })

                    except pefile.PEFormatError as e_pe_delay: # RVA out of bounds, etc.
                        logger.debug(f"Delay-load import table parsing error (PEFormatError at RVA {hex(current_thunk_rva)}): {e_pe_delay}")
                        delay_dll_info['imported_symbols_via_delay_load'].append({'error': f"PEFormatError at RVA {hex(current_thunk_rva)}: {e_pe_delay}"})
                        break # Stop parsing this DLL's delay-load symbols
                    except Exception as e_gen_delay:
                        logger.warning(f"Unexpected error parsing delay-load import entry at RVA {hex(current_thunk_rva)}: {e_gen_delay}")
                        delay_dll_info['imported_symbols_via_delay_load'].append({'error': f"Unexpected error at RVA {hex(current_thunk_rva)}: {e_gen_delay}"})
                        break
            delay_imports_list.append(delay_dll_info)
    return delay_imports_list


def _parse_tls_info(pe: pefile.PE, magic_type_str: str) -> Optional[Dict[str, Any]]:
    """Parses Thread Local Storage (TLS) directory, including callbacks if present."""
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and \
       hasattr(pe.DIRECTORY_ENTRY_TLS, 'struct') and pe.DIRECTORY_ENTRY_TLS.struct:
        
        tls_struct_obj = pe.DIRECTORY_ENTRY_TLS.struct # This is IMAGE_TLS_DIRECTORY
        tls_info: Dict[str, Any] = {'tls_directory_struct': tls_struct_obj.dump_dict()}
        
        parsed_callbacks: List[Dict[str, Any]] = []
        # AddressOfCallBacks is a VA (Virtual Address) to an array of PIMAGE_TLS_CALLBACK function pointers
        callbacks_array_va = getattr(tls_struct_obj, 'AddressOfCallBacks', 0)
        
        if callbacks_array_va != 0 and hasattr(pe, 'OPTIONAL_HEADER'):
            image_base = getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0)
            ptr_size_bytes = 8 if magic_type_str.startswith("PE32+") else 4
            max_callbacks_to_parse = 32 # Safety limit for number of callbacks

            current_callback_va_ptr = callbacks_array_va
            for i in range(max_callbacks_to_parse):
                try:
                    # Convert VA of the pointer to RVA, then to file offset to read the actual function VA
                    callback_func_va_rva_ptr = current_callback_va_ptr - image_base
                    
                    function_pointer_value = 0
                    if ptr_size_bytes == 8:
                        function_pointer_value = pe.get_qword_at_rva(callback_func_va_rva_ptr)
                    else: # ptr_size_bytes == 4
                        function_pointer_value = pe.get_dword_at_rva(callback_func_va_rva_ptr)

                    if function_pointer_value == 0: # Null pointer terminates the callback array
                        break
                    
                    callback_function_rva = function_pointer_value - image_base
                    parsed_callbacks.append({
                        'callback_function_va': hex(function_pointer_value),
                        'callback_function_rva': hex(callback_function_rva),
                        'pointer_to_callback_va': hex(current_callback_va_ptr)
                    })
                    current_callback_va_ptr += ptr_size_bytes # Move to the next pointer in the array
                
                except pefile.PEFormatError as e_pe_tls: # RVA out of bounds, etc.
                    logger.debug(f"TLS callback array parsing error (PEFormatError at VA_ptr {hex(current_callback_va_ptr)}): {e_pe_tls}")
                    parsed_callbacks.append({'error': f"PEFormatError parsing callback array at VA_ptr {hex(current_callback_va_ptr)}: {e_pe_tls}"})
                    break 
                except AttributeError as e_attr_tls: # e.g. if OPTIONAL_HEADER.ImageBase is missing
                    logger.warning(f"TLS callback parsing error (AttributeError, possibly missing ImageBase): {e_attr_tls}")
                    parsed_callbacks.append({'error': f"AttributeError during TLS callback parsing: {e_attr_tls}"})
                    break
                except Exception as e_gen_tls:
                    logger.warning(f"Unexpected error parsing TLS callback at VA_ptr {hex(current_callback_va_ptr)}: {e_gen_tls}")
                    parsed_callbacks.append({'error': f"Unexpected error at VA_ptr {hex(current_callback_va_ptr)}: {e_gen_tls}"})
                    break
        else: # No callbacks or cannot determine ImageBase
            if callbacks_array_va == 0:
                 tls_info['callbacks_status_note'] = "AddressOfCallBacks is NULL (no TLS callbacks)."
            else:
                 tls_info['callbacks_status_note'] = "Cannot parse TLS callbacks (e.g., OptionalHeader.ImageBase missing)."


        tls_info['parsed_tls_callbacks'] = parsed_callbacks
        return tls_info
    return None # No TLS directory


def _parse_load_config(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    """Parses the Load Configuration directory, including Guard Flags."""
    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and pe.DIRECTORY_ENTRY_LOAD_CONFIG and \
       hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG, 'struct') and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
        
        load_config_struct_obj = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct # IMAGE_LOAD_CONFIG_DIRECTORY
        load_config_dict: Dict[str, Any] = {'load_config_directory_struct': load_config_struct_obj.dump_dict()}

        if hasattr(load_config_struct_obj, 'GuardFlags'):
            guard_flags_val = load_config_struct_obj.GuardFlags
            guard_flags_list_interpreted: List[str] = []
            # Common Guard Flags from winnt.h (values might vary slightly or need checking against pefile's constants if available)
            # These are illustrative; pefile itself doesn't typically define these string names.
            # Consult winnt.h for IMAGE_GUARD_* constants for precise definitions.
            guard_flags_map = {
                0x00000100: "CF_INSTRUMENTED (Control Flow Guard instrumented)",
                0x00000200: "CFW_INSTRUMENTED (Control Flow Guard write-integrity instrumented)", # CFW_INSTRUMENTED is often same as CF_INSTRUMENTED in practice
                0x00000400: "CF_FUNCTION_TABLE_PRESENT (CFG function table present)",
                0x00000800: "SECURITY_COOKIE_UNUSED (GS security cookie not used /GS-)", # Obsolete/Rare
                0x00001000: "PROTECT_DELAYLOAD_IAT (Delayload IAT section is protected)",
                0x00002000: "DELAYLOAD_IAT_IN_ITS_OWN_SECTION (Delayload IAT in its own .didat section)",
                0x00004000: "CF_EXPORT_SUPPRESSION_INFO_PRESENT (CFG export suppression info present)",
                0x00008000: "CF_ENABLE_EXPORT_SUPPRESSION (Enable CFG export suppression)",
                0x00010000: "CF_LONGJUMP_TABLE_PRESENT (CFG longjump table present)",
                # Newer flags (may not be in all pefile versions' struct definitions directly)
                0x00100000: "RETPOLINE_PRESENT (Return Flow Guard / Retpoline)", # IMAGE_GUARD_RETPOLINE_PRESENT
                0x01000000: "EH_CONTINUATION_TABLE_PRESENT", # IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT
                0x02000000: "XFG_ENABLED (eXtended Flow Guard enabled)", # IMAGE_GUARD_XFG_ENABLED
                # 0x04000000: "MEMTAG_PRESENT" (ARM64 specific, less common for x86/x64 PE)
                0x08000000: "CET_SHADOW_STACK_PRESENT" # IMAGE_GUARD_CET_SHADOW_STACK_PRESENT (Intel CET)
            }
            for flag_val_map, flag_name_map in guard_flags_map.items():
                if guard_flags_val & flag_val_map:
                    guard_flags_list_interpreted.append(f"IMAGE_GUARD_{flag_name_map}")
            
            load_config_dict['guard_flags_interpreted'] = guard_flags_list_interpreted if guard_flags_list_interpreted else ["NONE_KNOWN_GUARD_FLAGS_SET"]
        else:
            load_config_dict['guard_flags_interpreted'] = ["GuardFlags field not present in parsed struct."]
            
        return load_config_dict
    return None # No Load Config directory


def _parse_com_descriptor(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    """Parses the .NET COM Descriptor (Cor20Header) if present."""
    com_desc_dir_idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR')
    if com_desc_dir_idx is None: # Should always be in pefile.DIRECTORY_ENTRY
        logger.warning("COM Descriptor: 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR' key not found in pefile.DIRECTORY_ENTRY map.")
        return None

    if hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and \
       len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > com_desc_dir_idx and \
       pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_desc_dir_idx].VirtualAddress != 0 and \
       hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR and \
       hasattr(pe.DIRECTORY_ENTRY_COM_DESCRIPTOR, 'struct') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct:
        
        com_desc_struct_obj = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct # IMAGE_COR20_HEADER
        com_dict: Dict[str, Any] = {'com_descriptor_cor20_header_struct': com_desc_struct_obj.dump_dict()}
        
        flags_list_interpreted: List[str] = []
        if hasattr(com_desc_struct_obj, 'Flags'):
            com_flags_val = com_desc_struct_obj.Flags
            # Common COMIMAGE_FLAGS from CorHdr.h
            com_flags_map = {
                0x00000001: "ILONLY (MSIL only, no native code)",
                0x00000002: "32BITREQUIRED (Requires 32-bit process)",
                0x00000004: "IL_LIBRARY (IL library, not executable - obsolete)", # Obsolete
                0x00000008: "STRONGNAMESIGNED (Assembly is strong name signed)",
                0x00000010: "NATIVE_ENTRYPOINT (Entry point is native, not MSIL - for mixed-mode)",
                # 0x00000020: "TRACKDEBUGDATA" (pefile uses this name, older was PREFER_32BIT)
                # The flag 0x20 was COMIMAGE_FLAGS_32BITPREFERRED (Prefer 32-bit process on 64-bit OS)
                # It seems pefile might map this to TRACKDEBUGDATA in some contexts or vice-versa.
                # Let's use the common interpretation for 0x20.
                0x00000020: "32BITPREFERRED (Prefer 32-bit process if AnyCPU)", # COMIMAGE_FLAGS_32BITPREFERRED
                0x00010000: "TRACKDEBUGDATA (Track debug data, from .NET 2.0+)" # COMIMAGE_FLAGS_TRACKDEBUGDATA
            }
            for flag_val_map, flag_name_map in com_flags_map.items():
                if com_flags_val & flag_val_map:
                    flags_list_interpreted.append(f"COMIMAGE_FLAGS_{flag_name_map}")
            
            com_dict['flags_interpreted'] = flags_list_interpreted if flags_list_interpreted else ["NONE_KNOWN_COMIMAGE_FLAGS_SET"]
        else:
            com_dict['flags_interpreted'] = ["Flags field not present in parsed COM Descriptor struct."]
            
        return com_dict
    return None # No COM Descriptor


def _parse_overlay_data(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    """Parses information about overlay data appended to the PE file."""
    overlay_start_offset = pe.get_overlay_data_start_offset()
    if overlay_start_offset is not None:
        overlay_data_bytes = pe.get_overlay() # Returns bytes or None
        if overlay_data_bytes:
            return {
                'overlay_start_file_offset': hex(overlay_start_offset),
                'overlay_size_bytes': len(overlay_data_bytes),
                'overlay_md5': hashlib.md5(overlay_data_bytes).hexdigest(),
                'overlay_sha256': hashlib.sha256(overlay_data_bytes).hexdigest(),
                'overlay_data_sample_hex_first_64_bytes': overlay_data_bytes[:64].hex()
            }
        else: # Offset found, but no data (e.g., zero-size overlay)
             return {
                'overlay_start_file_offset': hex(overlay_start_offset),
                'overlay_size_bytes': 0,
                'status_note': "Overlay offset found, but overlay data is empty."
            }
    return None # No overlay


def _parse_base_relocations(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses base relocation entries."""
    relocs_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') and isinstance(pe.DIRECTORY_ENTRY_BASERELOC, list):
        for base_reloc_block_obj in pe.DIRECTORY_ENTRY_BASERELOC: # BaseRelocationData instance
            block_info: Dict[str, Any] = {
                # base_reloc_block_obj.struct is IMAGE_BASE_RELOCATION
                'base_relocation_block_struct': base_reloc_block_obj.struct.dump_dict() if hasattr(base_reloc_block_obj, 'struct') else {},
                'relocation_entries_in_block': []
            }
            if hasattr(base_reloc_block_obj, 'entries') and isinstance(base_reloc_block_obj.entries, list):
                for reloc_entry_obj in base_reloc_block_obj.entries: # RelocationData instance
                    entry_data = {
                        'target_rva_of_relocation': hex(reloc_entry_obj.rva) if hasattr(reloc_entry_obj, 'rva') else "N/A",
                        'relocation_type_id': reloc_entry_obj.type if hasattr(reloc_entry_obj, 'type') else -1,
                        'relocation_type_string': get_relocation_type_str(reloc_entry_obj.type) if hasattr(reloc_entry_obj, 'type') else "N/A",
                        'is_padding_entry': getattr(reloc_entry_obj, 'is_padding', False) # Check if it's padding
                        # 'raw_relocation_entry_struct': reloc_entry_obj.struct.dump_dict() if hasattr(reloc_entry_obj, 'struct') else {}
                    }
                    block_info['relocation_entries_in_block'].append(entry_data)
            relocs_list.append(block_info)
    return relocs_list


def _parse_bound_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses bound import directory entries, if present."""
    bound_imports_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT') and isinstance(pe.DIRECTORY_ENTRY_BOUND_IMPORT, list):
        for bound_desc_obj in pe.DIRECTORY_ENTRY_BOUND_IMPORT: # BoundImportDescData instance
            desc_dict: Dict[str, Any] = {
                # bound_desc_obj.struct is IMAGE_BOUND_IMPORT_DESCRIPTOR
                'bound_import_descriptor_struct': bound_desc_obj.struct.dump_dict() if hasattr(bound_desc_obj, 'struct') else {},
                'bound_dll_name': "Unknown Bound DLL",
                'timestamp_iso_utc': format_timestamp(getattr(bound_desc_obj.struct, 'TimeDateStamp', 0)),
                'forwarder_references': []
            }
            try:
                # bound_desc_obj.name is bytes
                desc_dict['bound_dll_name'] = bound_desc_obj.name.decode('utf-8', 'ignore') if bound_desc_obj.name else "N/A (No Bound DLL Name)"
            except Exception as e_bound_dll_name:
                desc_dict['bound_dll_name'] = f"<Error decoding bound DLL name: {e_bound_dll_name}>"

            if hasattr(bound_desc_obj, 'entries') and isinstance(bound_desc_obj.entries, list):
                for fwd_ref_obj in bound_desc_obj.entries: # BoundFwdRefData instance
                    ref_dict: Dict[str, Any] = {
                        # fwd_ref_obj.struct is IMAGE_BOUND_FORWARDER_REF
                        'forwarder_ref_struct': fwd_ref_obj.struct.dump_dict() if hasattr(fwd_ref_obj, 'struct') else {},
                        'forwarded_dll_name': "Unknown Forwarded DLL",
                         'timestamp_iso_utc': format_timestamp(getattr(fwd_ref_obj.struct, 'TimeDateStamp', 0)),
                    }
                    try:
                        ref_dict['forwarded_dll_name'] = fwd_ref_obj.name.decode('utf-8', 'ignore') if fwd_ref_obj.name else "N/A (No Forwarded DLL Name)"
                    except Exception as e_fwd_name:
                        ref_dict['forwarded_dll_name'] = f"<Error decoding forwarded DLL name: {e_fwd_name}>"
                    desc_dict['forwarder_references'].append(ref_dict)
            bound_imports_list.append(desc_dict)
    return bound_imports_list


def _parse_exception_data(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses exception directory entries (e.g., RUNTIME_FUNCTION for x64)."""
    exception_data_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION') and isinstance(pe.DIRECTORY_ENTRY_EXCEPTION, list):
        machine_type = getattr(pe.FILE_HEADER, 'Machine', 0)
        for ex_entry_obj in pe.DIRECTORY_ENTRY_EXCEPTION: # ExceptionData instance (often RUNTIME_FUNCTION)
            entry_dump = {}
            note = "Generic Exception Entry"

            if hasattr(ex_entry_obj, 'struct') and ex_entry_obj.struct:
                entry_dump = ex_entry_obj.struct.dump_dict()
                # Add context based on machine type
                if machine_type == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_AMD64'): # x64
                    note = "x64 RUNTIME_FUNCTION (Unwind info at UnwindInfoAddressRVA/UnwindData RVA)"
                elif machine_type == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_I386'): # x86
                    # x86 exception handling is different, less common to see this dir populated this way
                    note = "x86 Exception Entry (Less common, SEH usually OS-handled or via code)"
                elif machine_type in [pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_ARMNT'), 
                                      pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_ARM64')]:
                    note = "ARM/ARM64 RUNTIME_FUNCTION"
            else: # Should not happen if DIRECTORY_ENTRY_EXCEPTION has entries
                entry_dump = {"error": "Exception entry struct not found."}

            exception_data_list.append({
                "exception_entry_struct_dump": entry_dump,
                "interpretation_note": note
            })
    return exception_data_list


def _parse_coff_symbols(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Parses COFF symbol table entries, including auxiliary symbols."""
    coff_symbols_list: List[Dict[str, Any]] = []
    if hasattr(pe, 'FILE_HEADER') and \
       getattr(pe.FILE_HEADER, 'PointerToSymbolTable', 0) != 0 and \
       getattr(pe.FILE_HEADER, 'NumberOfSymbols', 0) > 0 and \
       hasattr(pe, 'SYMBOLS') and isinstance(pe.SYMBOLS, list):
        
        symbol_table_index = 0
        while symbol_table_index < len(pe.SYMBOLS):
            symbol_obj = pe.SYMBOLS[symbol_table_index] # SymbolTableData instance
            
            name_str = "N/A"
            if hasattr(symbol_obj, 'name') and symbol_obj.name:
                try:
                    # Name can be short (in struct) or long (offset in string table)
                    # pefile handles resolving this into symbol_obj.name (bytes)
                    name_str = symbol_obj.name.decode('utf-8', 'ignore').rstrip('\x00')
                except Exception as e_coff_name:
                    name_str = f"<Error decoding COFF symbol name: {e_coff_name}>"
            
            sym_dict: Dict[str, Any] = {
                'symbol_table_index': symbol_table_index, # Original index in pe.SYMBOLS
                'name_decoded': name_str,
                'value': getattr(symbol_obj, 'Value', 0), # Symbol value (e.g., RVA for section symbols)
                'section_number': getattr(symbol_obj, 'SectionNumber', 0), # 1-based section index, or special values
                'type_raw': getattr(symbol_obj, 'Type', 0),
                'type_interpreted_str': get_symbol_type_str(getattr(symbol_obj, 'Type', 0)),
                'storage_class_raw': getattr(symbol_obj, 'StorageClass', 0),
                'storage_class_interpreted_str': get_symbol_storage_class_str(getattr(symbol_obj, 'StorageClass', 0)),
                'number_of_aux_symbols': getattr(symbol_obj, 'NumberOfAuxSymbols', 0),
                'raw_symbol_struct_dump': symbol_obj.struct.dump_dict() if hasattr(symbol_obj, 'struct') else {},
                'auxiliary_symbols_parsed': []
            }
            
            symbol_table_index += 1 # Move to next symbol/aux entry
            
            num_aux = getattr(symbol_obj, 'NumberOfAuxSymbols', 0)
            if num_aux > 0:
                for aux_record_idx_rel_to_parent in range(num_aux):
                    if symbol_table_index < len(pe.SYMBOLS):
                        # The auxiliary symbol record immediately follows its parent in pe.SYMBOLS
                        aux_symbol_raw_obj = pe.SYMBOLS[symbol_table_index]
                        # aux_symbol_raw_obj.struct is the actual auxiliary record structure
                        # (e.g., IMAGE_AUX_SYMBOL_FILENAME, IMAGE_AUX_SYMBOL_SECTIONDEF, etc.)
                        # or sometimes just raw bytes if pefile couldn't parse it specifically.
                        
                        parent_sym_struct_for_aux = symbol_obj.struct # Pass parent's main struct for context
                        aux_sym_struct_for_parsing = aux_symbol_raw_obj.struct if hasattr(aux_symbol_raw_obj, 'struct') else aux_symbol_raw_obj # Fallback to raw if no struct
                        
                        parsed_aux_dict = _dump_aux_symbol_to_dict(
                            parent_sym_struct_for_aux, 
                            aux_sym_struct_for_parsing, 
                            aux_record_idx_rel_to_parent
                        )
                        sym_dict['auxiliary_symbols_parsed'].append(parsed_aux_dict)
                        symbol_table_index += 1 # Consume this auxiliary symbol entry
                    else: # Should not happen if NumberOfAuxSymbols is correct
                        logger.warning(f"COFF symbol parsing: Expected auxiliary symbol for '{name_str}' but reached end of table.")
                        sym_dict['auxiliary_symbols_parsed'].append({"error": "Reached end of symbol table prematurely while expecting auxiliary symbol."})
                        break 
            coff_symbols_list.append(sym_dict)
    return coff_symbols_list


def _verify_checksum(pe: pefile.PE) -> Dict[str, Any]:
    """Verifies the PE file's checksum against the value in the Optional Header."""
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'CheckSum'):
        header_checksum_val = pe.OPTIONAL_HEADER.CheckSum
        calculated_checksum_val = pe.generate_checksum() # pefile calculates this
        
        matches_status = "Not applicable (Header checksum is 0)"
        if header_checksum_val != 0:
            matches_status = str(header_checksum_val == calculated_checksum_val)
            
        return {
            'checksum_from_optional_header': hex(header_checksum_val),
            'checksum_calculated_by_pefile': hex(calculated_checksum_val),
            'checksums_match_status': matches_status
        }
    return {"error": "Checksum information (OptionalHeader.CheckSum) not available in pefile object."}


# --- Main PE Parsing Logic ---
def _parse_pe_to_dict(pe: pefile.PE, filepath: str,
                      peid_db_path_str: Optional[str], # Resolved path
                      yara_rules_path_str: Optional[str], # Resolved path
                      capa_rules_dir_path_str: Optional[str], # Resolved path for capa rules dir
                      capa_sigs_dir_path_str: Optional[str],  # Resolved path for capa sigs dir
                      verbose: bool,
                      skip_full_peid_scan_arg: bool,
                      peid_scan_all_sigs_heuristically_arg: bool,
                      analyses_to_skip: Optional[List[str]] = None # List of lowercase analysis names to skip
                      ) -> Dict[str, Any]:
    """
    Orchestrates the parsing of a pefile.PE object into a comprehensive dictionary.
    Calls individual _parse_X helper functions for different PE structures and analyses.

    Args:
        pe: The initialized pefile.PE object.
        filepath: Absolute path to the PE file (for context and some tools like signify).
        peid_db_path_str: Resolved absolute path to the PEiD database.
        yara_rules_path_str: Resolved absolute path to YARA rules file/directory.
        capa_rules_dir_path_str: Resolved absolute path to Capa rules directory.
        capa_sigs_dir_path_str: Resolved absolute path to Capa signatures directory.
        verbose: Boolean for verbose logging output.
        skip_full_peid_scan_arg: For PEiD, if True, only scans entry point.
        peid_scan_all_sigs_heuristically_arg: For PEiD full scan, if True, uses all sigs.
        analyses_to_skip: Optional list of analysis types (e.g., "peid", "yara", "capa") to skip.

    Returns:
        A dictionary containing all parsed information.
    """
    global PEFILE_VERSION_USED # Store the pefile version used for this parse
    try:
        PEFILE_VERSION_USED = pefile.__version__
    except AttributeError:
        PEFILE_VERSION_USED = "Unknown (pefile.__version__ not found)"

    # Normalize analyses_to_skip to lowercase and ensure it's a list
    effective_analyses_to_skip = [analysis.lower() for analysis in analyses_to_skip] if analyses_to_skip else []
    if verbose: logger.debug(f"Parsing PE. Analyses to skip: {effective_analyses_to_skip}")

    pe_info_dict: Dict[str, Any] = {
        "source_filepath": filepath,
        "pefile_library_version_used": PEFILE_VERSION_USED,
        "parsing_timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    # --- Core PE Structure Parsing ---
    # These are generally always performed unless pefile itself fails.
    nt_headers_parsed_dict, magic_type_str_from_nt = _parse_nt_headers(pe) # Get magic_type early
    pe_info_dict['file_hashes_calculated'] = _parse_file_hashes(pe.__data__ if hasattr(pe, '__data__') else b'')
    pe_info_dict['dos_header_info'] = _parse_dos_header(pe)
    pe_info_dict['nt_headers_info'] = nt_headers_parsed_dict
    pe_info_dict['pe_architecture_string'] = magic_type_str_from_nt # Store determined PE type
    pe_info_dict['data_directories_info'] = _parse_data_directories(pe)
    pe_info_dict['sections_info'] = _parse_sections(pe)
    pe_info_dict['imports_info'] = _parse_imports(pe)
    pe_info_dict['exports_info'] = _parse_exports(pe)
    pe_info_dict['resources_summary_info'] = _parse_resources_summary(pe)
    pe_info_dict['version_info_parsed'] = _parse_version_info(pe)
    pe_info_dict['debug_info_parsed'] = _parse_debug_info(pe)
    pe_info_dict['digital_signature_info'] = _parse_digital_signature(pe, filepath, CRYPTOGRAPHY_AVAILABLE, SIGNIFY_AVAILABLE)
    pe_info_dict['rich_header_info'] = _parse_rich_header(pe)
    pe_info_dict['delay_load_imports_info'] = _parse_delay_load_imports(pe, magic_type_str_from_nt)
    pe_info_dict['tls_info_parsed'] = _parse_tls_info(pe, magic_type_str_from_nt)
    pe_info_dict['load_config_info'] = _parse_load_config(pe)
    pe_info_dict['com_descriptor_info'] = _parse_com_descriptor(pe)
    pe_info_dict['overlay_data_info'] = _parse_overlay_data(pe)
    pe_info_dict['base_relocations_info'] = _parse_base_relocations(pe)
    pe_info_dict['bound_imports_info'] = _parse_bound_imports(pe)
    pe_info_dict['exception_data_info'] = _parse_exception_data(pe)
    pe_info_dict['coff_symbols_info'] = _parse_coff_symbols(pe)
    pe_info_dict['checksum_verification_results'] = _verify_checksum(pe)

    # --- Conditional Analyses (PEiD, YARA, Capa) ---
    if "peid" not in effective_analyses_to_skip:
        if verbose: logger.info("Performing PEiD analysis...")
        pe_info_dict['peid_scan_analysis'] = _perform_peid_scan(
            pe, peid_db_path_str, verbose, 
            skip_full_peid_scan_arg, 
            peid_scan_all_sigs_heuristically_arg
        )
    else:
        logger.info("PEiD analysis skipped by request.")
        pe_info_dict['peid_scan_analysis'] = {"status": "Skipped by user request", "ep_only_matches": [], "heuristic_matches": [], "errors": ["Skipped via analyses_to_skip argument."]}

    if "yara" not in effective_analyses_to_skip:
        if YARA_AVAILABLE and yara_rules_path_str: # Only run if lib available and rules provided
            if verbose: logger.info(f"Performing YARA analysis with rules: {yara_rules_path_str}...")
            pe_info_dict['yara_scan_analysis'] = perform_yara_scan(
                filepath, pe.__data__ if hasattr(pe, '__data__') else b'', 
                yara_rules_path_str, YARA_AVAILABLE, verbose
            )
        elif not YARA_AVAILABLE:
            logger.info("YARA analysis skipped: yara-python library not available.")
            pe_info_dict['yara_scan_analysis'] = [{"status": "skipped", "reason": "yara-python library not available."}]
        else: # YARA_AVAILABLE is true, but no rules path
            logger.info("YARA analysis skipped: No YARA rules path provided.")
            pe_info_dict['yara_scan_analysis'] = [{"status": "skipped", "reason": "No YARA rules path provided."}]
    else:
        logger.info("YARA analysis skipped by request.")
        pe_info_dict['yara_scan_analysis'] = [{"status": "skipped", "reason": "Skipped via analyses_to_skip argument."}]

    if "capa" not in effective_analyses_to_skip:
        if CAPA_AVAILABLE: # Only run if lib available
            if verbose: logger.info("Performing Capa analysis...")
            pe_info_dict['capa_rules_analysis'] = _parse_capa_analysis(
                pe, filepath, capa_rules_dir_path_str, capa_sigs_dir_path_str, verbose
            )
        else:
            logger.info("Capa analysis skipped: Capa library (flare-capa) not available.")
            capa_err_msg = CAPA_IMPORT_ERROR if CAPA_IMPORT_ERROR else "Unknown import failure."
            pe_info_dict['capa_rules_analysis'] = {"status": "Skipped - Capa library not available.", "error": capa_err_msg, "results": None}
    else:
        logger.info("Capa analysis skipped by request.")
        pe_info_dict['capa_rules_analysis'] = {"status": "Skipped by user request", "error": "Skipped via analyses_to_skip argument.", "results": None}

    # --- Final pefile Warnings ---
    pe_info_dict['pefile_parsing_warnings'] = pe.get_warnings() if hasattr(pe, 'get_warnings') else ["get_warnings not available in this pefile version."]
    
    return pe_info_dict

# --- CLI Printing Helper Functions ---
# These functions take parts of the parsed PE dictionary and print them to the console.
# A global flag VERBOSE_CLI_OUTPUT_FLAG controls detailed output for some functions.
VERBOSE_CLI_OUTPUT_FLAG = False # Default, will be set by _cli_analyze_and_print_pe

def _print_dict_structure_cli(data_dict: Dict[str, Any], indent_level: int = 1, title: Optional[str] = None):
    """
    Recursively prints a dictionary structure for CLI output, typically used for pefile struct dumps.
    It attempts to pretty-print nested 'Value' dictionaries common in pefile's dump_dict() output.

    Args:
        data_dict: The dictionary to print.
        indent_level: Current indentation level for pretty printing.
        title: An optional title for this dictionary block.
    """
    prefix = "  " * indent_level
    if title:
        safe_print(f"{prefix}{title}:")
        # Adjust prefix for items if a title was printed, so items are further indented under the title
        item_prefix = "  " * (indent_level + 1)
    else:
        item_prefix = prefix # No title, items start at current indent_level

    for key, value in data_dict.items():
        # Skip pefile's internal structure representation if we are showing 'Value'
        if key == "Structure" and "Value" in data_dict: 
            continue
        
        # Handle pefile's common { 'Value': ..., 'Offset': ..., 'FileOffset': ...} structure
        if isinstance(value, dict) and "Value" in value and isinstance(value["Value"], dict):
            # If Value itself is a dict, recurse to print its structure
            _print_dict_structure_cli(value["Value"], indent_level + (1 if title else 2), title=key)
            # Optionally print Offset/FileOffset if verbose (or always if desired)
            if VERBOSE_CLI_OUTPUT_FLAG:
                offset_info = []
                if "Offset" in value: offset_info.append(f"Offset: {hex(value['Offset'])}")
                if "FileOffset" in value: offset_info.append(f"FileOffset: {hex(value['FileOffset'])}")
                if offset_info: safe_print(f"{item_prefix}  ({', '.join(offset_info)})")

        elif isinstance(value, list) and value and isinstance(value[0], dict) and \
             "Value" in value[0] and "Structure" in value[0]:
            # Handle lists of pefile struct-like dictionaries
            safe_print(f"{item_prefix}{key}:")
            for i, item_struct_container in enumerate(value):
                if isinstance(item_struct_container, dict) and "Value" in item_struct_container:
                     _print_dict_structure_cli(item_struct_container["Value"], indent_level + (2 if title else 3), title=f"Item {i+1}")
                else: # Should not happen if format is consistent
                    safe_print(f"{item_prefix}  Item {i+1}: {str(item_struct_container)[:200]}") # Truncate
        
        elif isinstance(value, list) or isinstance(value, tuple):
            # For simple lists/tuples, join elements, truncate if too long
            try:
                val_str = ', '.join(map(str, value)) if value else '[]'
            except Exception: # Handle if map(str,...) fails for complex list items
                val_str = "[Error converting list items to string]"
            if len(val_str) > 120 and not VERBOSE_CLI_OUTPUT_FLAG: 
                val_str = val_str[:117] + "..."
            safe_print(f"{item_prefix}{str(key):<30} {val_str}")
        else:
            # For other simple values, convert to string, truncate if too long
            try:
                val_str = str(value)
            except Exception:
                val_str = f"<Error converting value of type {type(value).__name__} to string>"

            if len(val_str) > 120 and not VERBOSE_CLI_OUTPUT_FLAG: 
                val_str = val_str[:117] + "..."
            safe_print(f"{item_prefix}{str(key):<30} {val_str}")


def _print_file_hashes_cli(hashes_dict: Dict[str, Any]):
    safe_print("\n--- File Hashes (Calculated) ---")
    if not hashes_dict: safe_print("  No hash data available."); return
    for algo, hash_val in hashes_dict.items():
        safe_print(f"  {algo.upper():<8}: {hash_val if hash_val else 'N/A or Error'}")

def _print_dos_header_cli(dos_header_data: Dict[str, Any]):
    safe_print("\n--- DOS Header (IMAGE_DOS_HEADER) ---")
    if not dos_header_data: safe_print("  DOS Header data not available."); return
    if "error" in dos_header_data:
        safe_print(f"  Error: {dos_header_data['error']}")
    else:
        # dos_header_data is the direct dump_dict() output
        # We want to print the 'Value' of each field.
        # Example: e_magic: {'Value': 23117, 'Offset': ...} -> print "e_magic: 23117"
        simplified_dos_header_values = {
            field: data.get('Value', 'N/A') 
            for field, data in dos_header_data.items() if isinstance(data, dict)
        }
        if not simplified_dos_header_values and dos_header_data: # If not in expected Value format, print raw
             _print_dict_structure_cli(dos_header_data, indent_level=1)
        else:
             _print_dict_structure_cli(simplified_dos_header_values, indent_level=1)


def _print_nt_headers_cli(nt_headers_data: Dict[str, Any]):
    safe_print("\n--- NT Headers (IMAGE_NT_HEADERS) ---")
    if not nt_headers_data: safe_print("  NT Headers data not available."); return
    if "error" in nt_headers_data:
        safe_print(f"  Error: {nt_headers_data['error']}")
        return
    
    safe_print(f"  Signature Hex:                   {nt_headers_data.get('signature_hex', 'N/A')}")

    if 'file_header' in nt_headers_data:
        safe_print("\n  --- File Header (IMAGE_FILE_HEADER) ---")
        fh_data = nt_headers_data['file_header']
        if "error" in fh_data: 
            safe_print(f"    Error: {fh_data['error']}")
        else:
            # fh_data is the dump_dict() of FileHeaderStructure
            simplified_fh_values = {
                field: data.get('Value', 'N/A')
                for field, data in fh_data.items() 
                if isinstance(data, dict) and field not in ['characteristics_interpreted', 'TimeDateStamp_iso_utc']
            }
            _print_dict_structure_cli(simplified_fh_values, indent_level=2)
            safe_print(f"    TimeDateStamp (Formatted UTC):   {fh_data.get('TimeDateStamp_iso_utc', 'N/A')}")
            safe_print(f"    Characteristics Flags:           {', '.join(fh_data.get('characteristics_interpreted', ['N/A']))}")
            
    if 'optional_header' in nt_headers_data:
        safe_print("\n  --- Optional Header (IMAGE_OPTIONAL_HEADER) ---")
        oh_data = nt_headers_data['optional_header']
        if "error" in oh_data:
            safe_print(f"    Error: {oh_data['error']}")
        else:
            simplified_oh_values = {
                field: data.get('Value', 'N/A')
                for field, data in oh_data.items()
                if isinstance(data, dict) and field not in ['dll_characteristics_interpreted', 'pe_architecture_type_string']
            }
            _print_dict_structure_cli(simplified_oh_values, indent_level=2)
            safe_print(f"    PE Architecture Type:            {oh_data.get('pe_architecture_type_string', 'N/A')}")
            safe_print(f"    DllCharacteristics Flags:        {', '.join(oh_data.get('dll_characteristics_interpreted', ['N/A']))}")

def _print_data_directories_cli(data_dirs_list: List[Dict[str, Any]]):
    safe_print("\n--- Data Directories (IMAGE_DATA_DIRECTORY Entries) ---")
    if not data_dirs_list: safe_print("  Data Directories not found or list is empty."); return
    
    for entry_dict in data_dirs_list:
        dir_name = entry_dict.get('directory_name', 'Unknown Directory')
        # Value for VirtualAddress and Size are inside the 'Value' dict of the main field from dump_dict
        # e.g. entry_dict = {'VirtualAddress': {'Value': 0x1000, ...}, 'Size': {'Value': 100, ...}, ...}
        rva_val = entry_dict.get('VirtualAddress', {}).get('Value', 0)
        size_val = entry_dict.get('Size', {}).get('Value', 0)

        # Only print if RVA or Size is non-zero, to reduce noise for empty directories
        if rva_val > 0 or size_val > 0:
            # For Security directory, RVA is actually a File Offset
            address_type_label = "File Offset" if dir_name == 'IMAGE_DIRECTORY_ENTRY_SECURITY' else "RVA"
            safe_print(f"  {dir_name:<35} {address_type_label}: {hex(rva_val):<12} Size: {hex(size_val)} ({size_val} bytes)")
        elif VERBOSE_CLI_OUTPUT_FLAG: # If verbose, show even empty ones
             safe_print(f"  {dir_name:<35} RVA: {hex(rva_val):<12} Size: {hex(size_val)} (Empty)")


def _print_sections_cli(sections_data_list: List[Dict[str, Any]], pe_obj_for_verbose: Optional[pefile.PE]):
    safe_print("\n--- Section Table (IMAGE_SECTION_HEADER Entries) ---")
    if not sections_data_list: safe_print("  No sections found in PE file."); return
    
    for section_dict_data in sections_data_list:
        sec_name = section_dict_data.get('name_decoded', 'Unknown Section')
        safe_print(f"\n  Section Name: {sec_name}")
        
        # section_dict_data is the dump_dict() of the SectionStructure
        simplified_section_header_values = {
            field: data.get('Value', 'N/A')
            for field, data in section_dict_data.items()
            if isinstance(data, dict) and field not in [
                'name_decoded', 'characteristics_interpreted', 'entropy_calculated',
                'data_md5', 'data_sha1', 'data_sha256', 'data_ssdeep' # These are added keys
            ]
        }
        _print_dict_structure_cli(simplified_section_header_values, indent_level=2)
        
        safe_print(f"    Characteristics Flags:           {', '.join(section_dict_data.get('characteristics_interpreted', ['N/A']))}")
        safe_print(f"    Entropy (Calculated):            {section_dict_data.get('entropy_calculated', 0.0):.4f}")
        if section_dict_data.get('data_md5'): safe_print(f"    Section Data MD5:                {section_dict_data.get('data_md5')}")
        if section_dict_data.get('data_ssdeep'): safe_print(f"    Section Data SSDeep:             {section_dict_data.get('data_ssdeep')}")
        
        if pe_obj_for_verbose and VERBOSE_CLI_OUTPUT_FLAG: # If verbose, try to print data sample
            try:
                # Find the pefile.SectionStructure object corresponding to this section_dict_data
                # This assumes 'name_decoded' is unique and matches pe_obj.sections[i].Name
                pe_sec_obj = next((s for s in pe_obj_for_verbose.sections if s.Name.decode('utf-8','ignore').rstrip('\x00') == sec_name), None)
                if pe_sec_obj:
                    sec_data_sample = pe_sec_obj.get_data(max_size=32) # Get first 32 bytes
                    if sec_data_sample:
                        safe_print(f"    Data Sample (first {len(sec_data_sample)} bytes):")
                        for dump_line in _format_hex_dump_lines(sec_data_sample, 0, 16): # Start address 0 for sample
                            safe_print(f"      {dump_line}")
                    else:
                        safe_print("    Data Sample: Section data is empty or could not be retrieved for sample.")
            except Exception as e_sec_sample:
                logger.debug(f"CLI Print: Error getting section data sample for '{sec_name}': {e_sec_sample}")
                safe_print("    Data Sample: Error retrieving data for sample.")


def _print_imports_cli(imports_data_list: List[Dict[str, Any]]):
    safe_print("\n--- Import Table (IAT/IDT) ---")
    if not imports_data_list: safe_print("  No import table found or it's empty."); return
    
    for dll_entry_dict in imports_data_list:
        dll_name = dll_entry_dict.get('dll_name', 'N/A DLL')
        safe_print(f"\n  DLL: {dll_name}")
        
        if "import_descriptor_struct" in dll_entry_dict and isinstance(dll_entry_dict["import_descriptor_struct"], dict):
            desc_struct_dump = dll_entry_dict["import_descriptor_struct"]
            if "error" not in desc_struct_dump:
                 simplified_desc_values = {
                    field: data.get('Value', 'N/A') for field, data in desc_struct_dump.items() if isinstance(data, dict)
                 }
                 _print_dict_structure_cli(simplified_desc_values, indent_level=2, title="Import Descriptor")
            else:
                 safe_print(f"    Import Descriptor: {desc_struct_dump.get('error', 'Unknown error')}")

        if not dll_entry_dict.get('imported_symbols'):
            safe_print("    No symbols imported from this DLL according to parsed data.")
            continue

        for imp_sym_dict in dll_entry_dict.get('imported_symbols', []):
            name_str = imp_sym_dict.get('name_decoded', "N/A (Likely imported by ordinal)")
            addr_rva_str = imp_sym_dict.get('address_rva', 'N/A') # RVA of the IAT entry
            ordinal_str = str(imp_sym_dict.get('ordinal_number', 'N/A'))
            by_ordinal_flag_str = "Yes" if imp_sym_dict.get('is_imported_by_ordinal') else "No"
            bound_str = f" (Bound to: {imp_sym_dict.get('bound_forwarder_rva')})" if imp_sym_dict.get('bound_forwarder_rva') else ""
            
            safe_print(f"    Symbol: {name_str}")
            safe_print(f"      RVA (IAT Entry): {addr_rva_str:<15} Ordinal: {ordinal_str:<6} Imported by Ordinal: {by_ordinal_flag_str}{bound_str}")
            if VERBOSE_CLI_OUTPUT_FLAG and imp_sym_dict.get('hint_name_table_rva'):
                 safe_print(f"      Hint/Name Table RVA: {imp_sym_dict['hint_name_table_rva']}")


def _print_exports_cli(exports_data_dict: Dict[str, Any]):
    safe_print("\n--- Export Table (EAT) ---")
    if not exports_data_dict or "error" in exports_data_dict:
        safe_print(f"  No export table found or error: {exports_data_dict.get('error', 'Data unavailable')}")
        return
        
    dll_name_exp = exports_data_dict.get('exported_dll_name', 'N/A')
    safe_print(f"  Exported DLL Name (from struct): {dll_name_exp}")

    if "export_directory_struct" in exports_data_dict and isinstance(exports_data_dict["export_directory_struct"], dict):
        dir_struct_dump = exports_data_dict["export_directory_struct"]
        if "error" not in dir_struct_dump:
            simplified_dir_values = {
                field: data.get('Value', 'N/A') for field, data in dir_struct_dump.items() if isinstance(data, dict)
            }
            _print_dict_structure_cli(simplified_dir_values, indent_level=1, title="Export Directory Structure")
        else:
            safe_print(f"    Export Directory Structure: {dir_struct_dump.get('error', 'Unknown error')}")
            
    if not exports_data_dict.get('exported_symbols'):
        safe_print("  No symbols exported from this PE file according to parsed data.")
        return

    for exp_sym_dict in exports_data_dict.get('exported_symbols', []):
        name_str = exp_sym_dict.get('name_decoded', "N/A (Exported by ordinal, no name)")
        addr_rva_str = exp_sym_dict.get('address_rva', 'N/A') # RVA of the exported function/data
        ordinal_str = str(exp_sym_dict.get('ordinal_number', 'N/A'))
        forwarder_str = f" -> FORWARDED TO: {exp_sym_dict.get('forwarder_string')}" if exp_sym_dict.get('forwarder_string') else ""
        
        safe_print(f"    Symbol: {name_str}")
        safe_print(f"      RVA (Export): {addr_rva_str:<15} Ordinal: {ordinal_str:<6}{forwarder_str}")


def _print_resources_summary_cli(resources_summary_list: List[Dict[str, Any]]):
    safe_print("\n--- Resource Directory (Summary of Entries) ---")
    if not resources_summary_list: safe_print("  No resource directory entries found or summary is empty."); return
    
    for res_item_dict in resources_summary_list:
        res_type = res_item_dict.get('resource_type', 'N/A Type')
        res_id_name = res_item_dict.get('resource_id_or_name', 'N/A ID/Name')
        res_lang = res_item_dict.get('language_sublanguage_str', res_item_dict.get('language_id', 'N/A Lang'))
        res_rva = res_item_dict.get('data_rva', 'N/A RVA')
        res_size = res_item_dict.get('data_size_bytes', 'N/A Size')
        
        safe_print(f"  - Type: {str(res_type):<30} ID/Name: {str(res_id_name):<30} Lang: {str(res_lang):<15} RVA: {str(res_rva):<12} Size: {res_size}")
        if VERBOSE_CLI_OUTPUT_FLAG and res_item_dict.get('codepage'):
            safe_print(f"    Codepage: {res_item_dict['codepage']}")


def _print_version_info_cli(ver_info_data: Dict[str, Any]):
    safe_print("\n--- Version Information (from RT_VERSION Resource) ---")
    if not ver_info_data or ver_info_data.get("status", "").startswith("Version info not found"):
        safe_print(f"  {ver_info_data.get('status', 'No version information found.')}")
        return

    if ver_info_data.get('vs_fixedfileinfo_entries'):
        safe_print("  VS_FIXEDFILEINFO:")
        for fixed_info_entry_dict in ver_info_data['vs_fixedfileinfo_entries']:
            # fixed_info_entry_dict is the dump_dict() of VS_FIXEDFILEINFOStructure
            simplified_ffi_values = {
                field: data.get('Value', 'N/A') for field, data in fixed_info_entry_dict.items()
                if isinstance(data, dict) and field not in ['file_version_formatted_str', 'product_version_formatted_str']
            }
            _print_dict_structure_cli(simplified_ffi_values, indent_level=2)
            safe_print(f"    File Version (Formatted):        {fixed_info_entry_dict.get('file_version_formatted_str', 'N/A')}")
            safe_print(f"    Product Version (Formatted):     {fixed_info_entry_dict.get('product_version_formatted_str', 'N/A')}")

    if ver_info_data.get('stringfileinfo_blocks'):
        safe_print("\n  StringFileInfo Blocks:")
        for sfi_block_dict in ver_info_data['stringfileinfo_blocks']:
            for st_table_dict in sfi_block_dict.get('string_tables', []):
                lang_cp = st_table_dict.get('lang_codepage_hex', 'N/A Lang/CP')
                safe_print(f"    StringTable (Language/Codepage: {lang_cp}):")
                if not st_table_dict.get('string_key_value_pairs'):
                    safe_print("      (No string entries in this table)")
                for key_str, val_str in st_table_dict.get('string_key_value_pairs', {}).items():
                    safe_print(f"      {key_str:<25}: {val_str}")
    
    if ver_info_data.get('varfileinfo_blocks'):
        safe_print("\n  VarFileInfo Blocks (Translations):")
        for vfi_block_dict in ver_info_data['varfileinfo_blocks']:
            for var_trans_dict in vfi_block_dict.get('vars_translations', []):
                for key_str, val_list_str in var_trans_dict.items(): # Usually one key "Translation"
                    safe_print(f"    {key_str}: {', '.join(val_list_str) if isinstance(val_list_str, list) else val_list_str}")
    
    if ver_info_data.get('vs_versioninfo_struct_key_string'):
        safe_print(f"\n  VS_VERSIONINFO Key String: {ver_info_data['vs_versioninfo_struct_key_string']}")


def _print_digital_signatures_cli(sig_info_data: Dict[str, Any]):
    safe_print("\n--- Digital Signatures (Authenticode) ---")
    if not sig_info_data: safe_print("  No signature information data available."); return

    status_msg = sig_info_data.get('status', 'Status unknown.')
    safe_print(f"  Overall Status: {status_msg}")

    if sig_info_data.get('security_directory_details'):
        sec_dir = sig_info_data['security_directory_details']
        safe_print(f"  Security Directory Entry: RVA/Offset: {sec_dir.get('virtual_address_rva', 'N/A')}, Size: {sec_dir.get('size_bytes', 'N/A')} bytes")

    if not sig_info_data.get('is_signed_according_to_directory', False):
        safe_print("  File does not appear to be directly signed (no valid security directory pointing to signature data).")
        safe_print("  Note: File might be signed via a Windows Catalog (.cat) file (not checked by this script).")
        return

    # Cryptography parsing status (informational, as signify handles the main parsing)
    crypto_status = sig_info_data.get('cryptography_parsing_status')
    if crypto_status: safe_print(f"  Cryptography Library Status: {crypto_status}")

    # Signify validation results
    signify_error = sig_info_data.get('signify_authenticode_validation_error')
    signify_status = sig_info_data.get('signify_authenticode_validation_status') # For "not available" case
    signify_results_list = sig_info_data.get('signify_authenticode_validation')

    if signify_error:
        safe_print(f"  Signify Validation Error: {signify_error}")
    elif signify_status: # e.g. "Signify library not available."
        safe_print(f"  Signify Validation Status: {signify_status}")
    elif not signify_results_list:
        safe_print("  Signify: No validation results returned, though library seems available.")
    else: # We have a list of results from signify
        safe_print("\n  --- Authenticode Validation Details (via 'signify') ---")
        for block_result_dict in signify_results_list:
            safe_print(f"\n    Signature Block Index: {block_result_dict.get('signature_block_index', 'N/A')}")
            safe_print(f"      Verification Status:         {block_result_dict.get('verification_status_code', 'N/A')} ({block_result_dict.get('verification_status_description', 'N/A')})")
            safe_print(f"      Considered Valid by Signify: {block_result_dict.get('is_considered_valid_by_signify', 'N/A')}")
            if block_result_dict.get('verification_exception_details'):
                safe_print(f"      Verification Exception:      {block_result_dict['verification_exception_details']}")
            
            signer_info_dict = block_result_dict.get('signer_info')
            if signer_info_dict:
                safe_print("      Signer Information:")
                safe_print(f"        Program Name:              {signer_info_dict.get('program_name', 'N/A')}")
                safe_print(f"        Issuer DN (RFC4514):       {signer_info_dict.get('issuer_dn_rfc4514', 'N/A')}")
                safe_print(f"        Serial Number (Hex):       {signer_info_dict.get('serial_number_hex', 'N/A')}")
                safe_print(f"        Timestamp (UTC):           {signer_info_dict.get('timestamp_utc', 'N/A')}")

            certs_chain_list = block_result_dict.get('certificates_chain', [])
            if certs_chain_list:
                safe_print("      Certificate Chain:")
                for cert_item_dict in certs_chain_list:
                    safe_print(f"        - Certificate Index in Chain: {cert_item_dict.get('chain_index', 'N/A')}")
                    safe_print(f"          Subject DN (RFC4514):    {cert_item_dict.get('subject_dn_rfc4514', 'N/A')}")
                    safe_print(f"          Issuer DN (RFC4514):     {cert_item_dict.get('issuer_dn_rfc4514', 'N/A')}")
                    if VERBOSE_CLI_OUTPUT_FLAG: # Only show more cert details if verbose
                        safe_print(f"          Serial (Hex):            {cert_item_dict.get('serial_number_hex', 'N/A')}")
                        safe_print(f"          Version:                 {cert_item_dict.get('version', 'N/A')}")
                        safe_print(f"          Valid Not Before (UTC):  {cert_item_dict.get('not_valid_before_utc', 'N/A')}")
                        safe_print(f"          Valid Not After (UTC):   {cert_item_dict.get('not_valid_after_utc', 'N/A')}")
            elif signer_info_dict: # If signer_info was there but no cert_chain (should be rare if signed)
                safe_print("      Certificate Chain:             (No detailed chain info parsed by this script from signify output)")


def _print_peid_matches_cli(peid_results_dict: Dict[str, Any]):
    safe_print("\n--- Packer/Compiler Detection (Custom PEiD Signatures) ---")
    if not peid_results_dict: safe_print("  PEiD scan data not available."); return

    status = peid_results_dict.get("status", "Unknown status.")
    safe_print(f"  Scan Status: {status}")
    if peid_results_dict.get("database_path_used"):
        safe_print(f"  Database Used: {peid_results_dict['database_path_used']}")

    if peid_results_dict.get("errors"):
        safe_print("  Errors during PEiD scan:")
        for err_msg in peid_results_dict["errors"]: safe_print(f"    - {err_msg}")
    
    if status == "Scan performed":
        ep_matches = peid_results_dict.get("ep_only_matches", [])
        heuristic_matches = peid_results_dict.get("heuristic_matches", [])
        
        if peid_results_dict.get("ep_scan_status_note"): # e.g. "Skipped (AddressOfEntryPoint is 0)"
            safe_print(f"  Entry Point Scan Note: {peid_results_dict['ep_scan_status_note']}")

        if ep_matches:
            safe_print("  Matches at Entry Point (All Signatures):")
            for match_name in set(ep_matches): safe_print(f"    - {match_name}")
        elif not peid_results_dict.get("ep_scan_status_note"): # If EP scan was attempted but no matches
            safe_print("  No PEiD signatures matched at entry point.")

        heuristic_scan_note = peid_results_dict.get("heuristic_scan_status_note")
        if heuristic_scan_note: # e.g. "Skipped by user request"
            safe_print(f"  Heuristic (Full File) Scan Note: {heuristic_scan_note}")
        elif heuristic_matches:
            # Show only heuristic matches that were NOT already found at EP for clarity
            additional_heuristic_only = sorted(list(set(heuristic_matches) - set(ep_matches)))
            if additional_heuristic_only:
                safe_print("\n  Additional Heuristic Matches (Scanned Sections):")
                for match_name in additional_heuristic_only: safe_print(f"    - {match_name}")
            elif not ep_matches and heuristic_matches : # No EP matches, but heuristic ones found
                 safe_print("\n  Heuristic Matches (Scanned Sections):")
                 for match_name in sorted(list(set(heuristic_matches))): safe_print(f"    - {match_name}")
        
        if not ep_matches and not heuristic_matches and not heuristic_scan_note and not peid_results_dict.get("ep_scan_status_note"):
            safe_print("  No PEiD signatures matched (neither at EP nor heuristically).")


def _print_yara_matches_cli(yara_results_list: List[Dict[str, Any]], yara_rules_path_used: Optional[str]):
    safe_print("\n--- YARA Scan Results ---")
    if not yara_results_list: safe_print("  YARA scan data not available or scan not performed."); return

    # Check for status messages like "skipped" or "error"
    if yara_results_list and isinstance(yara_results_list[0], dict):
        first_entry_status = yara_results_list[0].get("status")
        if first_entry_status in ["skipped", "error", "no_matches"]:
            safe_print(f"  YARA Status: {first_entry_status.replace('_',' ').title()}")
            if yara_results_list[0].get("reason"):
                safe_print(f"    Reason: {yara_results_list[0]['reason']}")
            if yara_results_list[0].get("details") and VERBOSE_CLI_OUTPUT_FLAG:
                 safe_print(f"    Details: {yara_results_list[0]['details']}")
            if yara_rules_path_used: safe_print(f"  Rules Path Attempted: {yara_rules_path_used}")
            return # Stop if it's just a status message

    # If we have actual matches (list of dicts without 'status' as primary key)
    actual_matches = [m for m in yara_results_list if isinstance(m, dict) and "rule_name" in m]
    if not actual_matches:
        safe_print("  No YARA rule matches found.")
        if yara_rules_path_used: safe_print(f"  Rules Path Used: {yara_rules_path_used}")
        return
        
    safe_print(f"  YARA Rules Matched ({len(actual_matches)}):")
    if yara_rules_path_used: safe_print(f"  Rules Path Used: {yara_rules_path_used}")

    for match_dict in actual_matches:
        safe_print(f"\n    Rule: {match_dict.get('rule_name', 'N/A')}")
        if match_dict.get('namespace') and match_dict['namespace'] != 'default':
            safe_print(f"      Namespace: {match_dict['namespace']}")
        if match_dict.get('tags'):
            safe_print(f"      Tags: {', '.join(match_dict['tags'])}")
        
        if match_dict.get('meta'):
            safe_print("      Meta:")
            for meta_key, meta_val in match_dict['meta'].items():
                safe_print(f"        {meta_key}: {str(meta_val)[:200]}") # Truncate long meta values
        
        strings_matched_list = match_dict.get('strings', [])
        if strings_matched_list:
            safe_print(f"      Matched Strings ({len(strings_matched_list)}):")
            for idx, str_match_dict in enumerate(strings_matched_list):
                if idx >= 5 and not VERBOSE_CLI_OUTPUT_FLAG: # Limit string details if not verbose
                    safe_print(f"        ... ({len(strings_matched_list) - idx} more matched strings not shown, use --verbose)")
                    break
                offset_str = str_match_dict.get('offset', 'N/A')
                identifier_str = str_match_dict.get('identifier', 'N/A')
                data_repr_str = str_match_dict.get('matched_data_repr', 'N/A')
                safe_print(f"        Offset: {offset_str}, ID: {identifier_str}, Data: {data_repr_str}")


def _print_capa_analysis_cli(capa_analysis_data: Dict[str, Any], verbose_flag: bool): # verbose_flag from main CLI args
    safe_print("\n--- Capa Capability Analysis ---")
    if not capa_analysis_data: safe_print("  Capa analysis data not available."); return

    status = capa_analysis_data.get("status", "Unknown status")
    safe_print(f"  Capa Overall Status: {status}")

    if capa_analysis_data.get("error"):
        safe_print(f"  Capa Error Details: {capa_analysis_data['error']}")
    
    # Even if error, results might have partial metadata
    results_dict = capa_analysis_data.get("results")
    if not results_dict:
        if status not in ["Skipped by user request", "Skipped - Capa library not available."]: # Avoid redundant message if already skipped
             safe_print("  No capa results structure found in the analysis data.")
        return

    # Print Metadata from capa results
    meta_from_results = results_dict.get("meta", {})
    if meta_from_results:
        safe_print("\n  Capa Report Metadata:")
        if meta_from_results.get("timestamp"):
            safe_print(f"    Report Timestamp: {meta_from_results['timestamp']}")
        if meta_from_results.get("version"):
            safe_print(f"    Capa Version Used: {meta_from_results['version']}")
        
        analysis_meta = meta_from_results.get("analysis", {})
        if analysis_meta:
            safe_print("    Analysis Parameters:")
            safe_print(f"      Input Sample MD5: {analysis_meta.get('sample',{}).get('md5','N/A')}")
            safe_print(f"      Format: {analysis_meta.get('format', 'N/A')}, Arch: {analysis_meta.get('arch', 'N/A')}, OS: {analysis_meta.get('os', 'N/A')}")
            safe_print(f"      Extractor: {analysis_meta.get('extractor', 'N/A')}")
            if verbose_flag and analysis_meta.get('rules'): # Rules paths used
                safe_print(f"      Rules Paths Used by Capa: {', '.join(analysis_meta.get('rules', []))}")
            if verbose_flag and analysis_meta.get('feature_counts'):
                 safe_print(f"      Feature Counts: {analysis_meta['feature_counts']}")
    
    # Print Detected Capabilities (Rules)
    rules_from_results = results_dict.get("rules", {})
    if not rules_from_results:
        safe_print("\n  No capabilities (rules) detected or reported by capa.")
        return

    safe_print(f"\n  Detected Capabilities ({len(rules_from_results)}):")
    capability_count_printed = 0
    for rule_id, rule_details_dict in rules_from_results.items():
        if not isinstance(rule_details_dict, dict): continue # Skip malformed rule entries

        rule_meta_info = rule_details_dict.get("meta", {})
        if not isinstance(rule_meta_info, dict): rule_meta_info = {}

        capability_name = rule_meta_info.get("name", rule_id) # Fallback to rule_id if name missing
        safe_print(f"\n    Capability: {capability_name}")
        if rule_meta_info.get('namespace'):
            safe_print(f"      Namespace: {rule_meta_info['namespace']}")
        
        # ATT&CK and MBC mappings
        for tactic_key, tactic_name_display in [("att&ck", "ATT&CK Tactic/Technique"), ("mbc", "MBC Objective/Behavior")]:
            entries = rule_meta_info.get(tactic_key, [])
            if entries:
                display_list = []
                for entry_item in entries: # entry_item can be str or dict
                    if isinstance(entry_item, dict): # e.g. {"tactic": "Discovery", "technique": "File and Directory Discovery", "id": "T1083"}
                        # Try to build a comprehensive string
                        parts = [entry_item.get('id', '')]
                        if 'tactic' in entry_item: parts.append(f"Tactic: {entry_item['tactic']}")
                        if 'technique' in entry_item: parts.append(f"Technique: {entry_item['technique']}")
                        if 'objective' in entry_item: parts.append(f"Objective: {entry_item['objective']}") # For MBC
                        if 'behavior' in entry_item: parts.append(f"Behavior: {entry_item['behavior']}")   # For MBC
                        display_str = " - ".join(filter(None, parts)) # Filter out empty parts
                        if not display_str: display_str = str(entry_item) # Fallback if all parts were empty
                        display_list.append(display_str)
                    else: # Simple string entry
                        display_list.append(str(entry_item))
                if display_list:
                    safe_print(f"      {tactic_name_display}: {'; '.join(display_list)}")

        if verbose_flag: # More details if verbose
            if rule_meta_info.get('description'):
                safe_print(f"      Description: {rule_meta_info['description']}")
            if rule_meta_info.get('authors'):
                safe_print(f"      Authors: {', '.join(rule_meta_info.get('authors',[]))}")
            if rule_meta_info.get('scopes',{}).get('static'): # e.g. "file", "function"
                 safe_print(f"      Scope (Static): {rule_meta_info['scopes']['static']}")
            if rule_meta_info.get('scopes',{}).get('dynamic'):
                 safe_print(f"      Scope (Dynamic): {rule_meta_info['scopes']['dynamic']}")


        # Matches (locations where the rule matched)
        matches_info = rule_details_dict.get("matches", {}) # This is a dict: address_str -> list_of_feature_matches
        if isinstance(matches_info, dict) and matches_info:
            safe_print(f"      Match Locations ({len(matches_info)} unique addresses):")
            match_addr_count_printed = 0
            for addr_hex_str, feature_match_list_at_addr in matches_info.items():
                if not verbose_flag and match_addr_count_printed >= 3: # Limit addresses shown if not verbose
                    safe_print(f"        ... (additional match locations for this rule omitted, use --verbose for all)")
                    break
                safe_print(f"        At Address: {addr_hex_str}")
                
                if verbose_flag and isinstance(feature_match_list_at_addr, list):
                    for feat_idx, feat_match_detail in enumerate(feature_match_list_at_addr):
                        if feat_idx >=3 and not verbose_flag: # Further limit features per address if extremely verbose
                             safe_print(f"          ... (further feature details at this address omitted)")
                             break
                        # feat_match_detail is complex, often contains 'feature': {'type': ..., 'value': ..., 'description': ...}
                        feature_obj = feat_match_detail.get('feature', {}) if isinstance(feat_match_detail, dict) else {}
                        feat_type = feature_obj.get('type', 'N/A')
                        feat_val = str(feature_obj.get('value', 'N/A'))[:80] # Truncate long values
                        feat_desc = str(feature_obj.get('description', ''))[:100] # Truncate
                        
                        node_obj = feat_match_detail.get('node', {}) if isinstance(feat_match_detail, dict) else {}
                        node_type = node_obj.get('type', 'N/A')
                        node_text = str(node_obj.get('text', ''))[:80]


                        display_parts = [f"Feature Type: {feat_type}", f"Value: {feat_val}"]
                        if feat_desc: display_parts.append(f"Desc: {feat_desc}")
                        if node_type != 'N/A' or node_text:
                            display_parts.append(f"Node Type: {node_type}")
                            if node_text : display_parts.append(f"Node Text: {node_text}")

                        safe_print(f"          - {' | '.join(display_parts)}")
                match_addr_count_printed += 1
        elif not matches_info: # Empty matches dict
            safe_print("      Match Locations: No specific address match locations reported for this rule.")
        
        capability_count_printed += 1
        if not verbose_flag and capability_count_printed >= 10: # Limit total capabilities shown if not verbose
            safe_print("\n  ... (additional capabilities omitted, use --verbose to see all)")
            break


def _print_rich_header_cli(rich_header_data: Optional[Dict[str, Any]]):
    safe_print("\n--- Rich Header Information ---")
    if not rich_header_data: safe_print("  No Rich Header found or data is empty."); return
    
    safe_print(f"  XOR Key (Hex):                      {rich_header_data.get('xor_key_hex', 'N/A')}")
    safe_print(f"  Checksum (from Rich Header Struct): {rich_header_data.get('checksum_from_header_struct', 'N/A')}")
    
    decoded_entries = rich_header_data.get('decoded_compid_entries', [])
    if decoded_entries:
        safe_print("  Decoded CompID Entries (ProductID / BuildNumber / Count):")
        for entry_dict in decoded_entries:
            prod_id_hex = entry_dict.get('product_id_decoded_hex', 'N/A')
            prod_id_dec = entry_dict.get('product_id_decoded_decimal', 'N/A')
            build_num = entry_dict.get('build_number_decoded', 'N/A')
            count = entry_dict.get('occurrence_count', 'N/A')
            raw_comp_id = entry_dict.get('raw_comp_id_dword', 'N/A')
            safe_print(f"    - ProductID: {prod_id_hex} (Dec: {prod_id_dec}), Build: {build_num}, Count: {count} (Raw CompID: {raw_comp_id})")
    else:
        safe_print("  No decoded CompID entries found in Rich Header data.")

    if VERBOSE_CLI_OUTPUT_FLAG:
        if rich_header_data.get('raw_rich_header_data_hex'):
            safe_print(f"  Raw Rich Header Data (Hex Snippet):    {rich_header_data['raw_rich_header_data_hex'][:128]}...")
        if rich_header_data.get('decrypted_rich_header_data_hex'):
            safe_print(f"  Decrypted Rich Header Data (Hex Snippet): {rich_header_data['decrypted_rich_header_data_hex'][:128]}...")


def _print_coff_symbols_cli(coff_symbols_list: List[Dict[str, Any]], verbose_flag: bool): # verbose_flag from main CLI
    safe_print("\n--- COFF Symbol Table ---")
    if not coff_symbols_list: safe_print("  No COFF Symbol Table found or it's empty."); return
    
    limit_symbols_to_print = None if verbose_flag else 30 # Show more if verbose
    displayed_count = 0
    safe_print(f"  Total COFF Symbol Records (including auxiliaries if counted by pefile): {len(coff_symbols_list)}") # pe.SYMBOLS includes aux
    
    for i, sym_data_dict in enumerate(coff_symbols_list):
        if limit_symbols_to_print is not None and displayed_count >= limit_symbols_to_print:
            safe_print(f"  ... (omitting remaining {len(coff_symbols_list) - displayed_count} COFF symbols, use --verbose for all)")
            break
        
        sym_name = sym_data_dict.get('name_decoded', 'N/A')
        safe_print(f"\n  Symbol Index (in pe.SYMBOLS): {sym_data_dict.get('symbol_table_index', i)}: {sym_name}")
        safe_print(f"    Value (e.g., RVA/Offset):    {hex(sym_data_dict.get('value',0))}")
        safe_print(f"    SectionNumber:               {sym_data_dict.get('section_number')} (0=undef, -1=abs, -2=debug, >0=section index)")
        safe_print(f"    Type (Raw / Interpreted):    {hex(sym_data_dict.get('type_raw',0))} / {sym_data_dict.get('type_interpreted_str', 'N/A')}")
        safe_print(f"    StorageClass (Raw / Interp): {sym_data_dict.get('storage_class_raw')} / {sym_data_dict.get('storage_class_interpreted_str', 'N/A')}")
        safe_print(f"    NumberOfAuxSymbols:          {sym_data_dict.get('number_of_aux_symbols')}")

        if verbose_flag and sym_data_dict.get('raw_symbol_struct_dump'):
            _print_dict_structure_cli(sym_data_dict['raw_symbol_struct_dump'], indent_level=3, title="Raw Symbol Struct")

        aux_symbols_parsed_list = sym_data_dict.get('auxiliary_symbols_parsed', [])
        if aux_symbols_parsed_list:
            safe_print("    Auxiliary Symbol(s):")
            for aux_sym_dict in aux_symbols_parsed_list:
                aux_type = aux_sym_dict.get('type', 'Unknown Aux Type')
                safe_print(f"      Aux Record Index (Relative): {aux_sym_dict.get('aux_record_index', 'N/A')}, Type: {aux_type}")
                # Print other fields from the parsed aux dict
                for k, v_aux in aux_sym_dict.items():
                    if k not in ['aux_record_index', 'type', 'interpretation_status']: # Avoid re-printing these
                        safe_print(f"        {k.replace('_', ' ').title()}: {v_aux}")
                if aux_sym_dict.get('interpretation_status') != "Interpreted" and verbose_flag:
                    safe_print(f"        Interpretation Note: {aux_sym_dict.get('interpretation_status')}")
        displayed_count += 1


def _print_pefile_warnings_cli(warnings_list: List[str]):
    safe_print("\n--- PEFile Library Parsing Warnings ---")
    if warnings_list:
        safe_print("  Warnings reported by 'pefile' during parsing:")
        for warning_msg in warnings_list:
            safe_print(f"    - {warning_msg}")
    else:
        safe_print("  No warnings reported by 'pefile' during parsing.")


# --- Main CLI Printing Function ---
def _cli_analyze_and_print_pe(filepath_to_analyze: str, 
                              resolved_peid_db_path: Optional[str],
                              resolved_yara_rules_path: Optional[str],
                              resolved_capa_rules_dir: Optional[str], 
                              resolved_capa_sigs_dir: Optional[str],
                              verbose_output_flag: bool, # Main verbose flag from args
                              arg_skip_full_peid_scan: bool, 
                              arg_peid_scan_all_sigs_heuristically: bool,
                              arg_extract_strings_cli: bool, 
                              arg_min_str_len_cli: int,
                              arg_search_strings_cli: Optional[List[str]], 
                              arg_strings_limit_cli: int,
                              arg_hexdump_offset_cli: Optional[int], 
                              arg_hexdump_length_cli: Optional[int],
                              arg_hexdump_lines_cli: int,
                              arg_analyses_to_skip_list: Optional[List[str]] = None
                              ):
    """
    Main function for CLI mode: loads PE, calls main parser, then calls print helpers.
    Handles exceptions during PE loading and analysis for CLI mode.
    """
    global PEFILE_VERSION_USED, VERBOSE_CLI_OUTPUT_FLAG # Set global for helper print functions
    VERBOSE_CLI_OUTPUT_FLAG = verbose_output_flag 
    
    # Resolve pefile version for logging/reporting (done again here for CLI specific context if needed)
    pefile_version_str = "unknown"
    try: pefile_version_str = pefile.__version__
    except AttributeError: pass

    if verbose_output_flag: 
        logger.info(f"CLI Mode: Starting analysis for: {filepath_to_analyze}. (pefile version: {pefile_version_str})")
    
    safe_print(f"[*] Analyzing PE file: {filepath_to_analyze}\n")
    
    pe_obj_for_cli_analysis: Optional[pefile.PE] = None 
    try:
        # Load the PE file. fast_load=False is generally better for full, detailed analysis.
        # fast_load=True can be quicker if only basic info or specific directories are needed.
        # For a comprehensive analyzer, False is safer.
        pe_obj_for_cli_analysis = pefile.PE(filepath_to_analyze, fast_load=False)
        
        # Perform the core parsing using the main helper that returns the comprehensive dictionary
        cli_pe_info_dict = _parse_pe_to_dict(
            pe_obj_for_cli_analysis, filepath_to_analyze, 
            resolved_peid_db_path, resolved_yara_rules_path,
            resolved_capa_rules_dir, resolved_capa_sigs_dir,
            verbose_output_flag, 
            arg_skip_full_peid_scan, arg_peid_scan_all_sigs_heuristically,
            analyses_to_skip=arg_analyses_to_skip_list # Pass the skip list
        )

        # --- Print all the standard PE information sections ---
        _print_file_hashes_cli(cli_pe_info_dict.get('file_hashes_calculated', {}))
        _print_dos_header_cli(cli_pe_info_dict.get('dos_header_info', {}))
        _print_nt_headers_cli(cli_pe_info_dict.get('nt_headers_info', {}))
        _print_data_directories_cli(cli_pe_info_dict.get('data_directories_info', []))
        # Pass pe_obj for verbose data sample in _print_sections_cli
        _print_sections_cli(cli_pe_info_dict.get('sections_info', []), pe_obj_for_cli_analysis) 
        _print_imports_cli(cli_pe_info_dict.get('imports_info', []))
        _print_exports_cli(cli_pe_info_dict.get('exports_info', {}))
        _print_resources_summary_cli(cli_pe_info_dict.get('resources_summary_info', []))
        _print_version_info_cli(cli_pe_info_dict.get('version_info_parsed', {}))
        _print_digital_signatures_cli(cli_pe_info_dict.get('digital_signature_info', {}))
        
        # --- Print analysis results (PEiD, YARA, Capa) ---
        _print_peid_matches_cli(cli_pe_info_dict.get('peid_scan_analysis', {}))
        _print_yara_matches_cli(cli_pe_info_dict.get('yara_scan_analysis', []), resolved_yara_rules_path)
        _print_capa_analysis_cli(cli_pe_info_dict.get('capa_rules_analysis', {}), verbose_output_flag)

        # --- Print other PE structures ---
        _print_rich_header_cli(cli_pe_info_dict.get('rich_header_info'))

        # Generic printing for remaining structures that are dictionaries or lists of dictionaries
        # This simplifies adding new parsed structures to the CLI output.
        # Key in cli_pe_info_dict -> Title for CLI output
        remaining_structures_to_print_config = [
            ("delay_load_imports_info", "Delay-Load Imports Information"),
            ("tls_info_parsed", "Thread Local Storage (TLS) Information"),
            ("load_config_info", "Load Configuration Directory Information"),
            ("com_descriptor_info", ".NET COM Descriptor (Cor20Header) Information"),
            ("overlay_data_info", "Overlay Data (Appended to File) Information"),
            ("base_relocations_info", "Base Relocations Information"),
            ("bound_imports_info", "Bound Imports Information"),
            ("exception_data_info", "Exception Handling Data Information"),
            ("checksum_verification_results", "Checksum Verification Results")
            # COFF Symbols are handled by their own more detailed printer
        ]
        for data_key, cli_title_str in remaining_structures_to_print_config:
            data_item_to_print = cli_pe_info_dict.get(data_key)
            safe_print(f"\n--- {cli_title_str} ---")
            if data_item_to_print is not None and data_item_to_print != {} and data_item_to_print != []:
                if isinstance(data_item_to_print, list) and data_item_to_print:
                    for i, item_in_list_generic in enumerate(data_item_to_print):
                        if isinstance(item_in_list_generic, dict):
                            # Use _print_dict_structure_cli for nested dicts, or a simpler print
                            _print_dict_structure_cli(item_in_list_generic, indent_level=1, title=f"Entry {i+1}")
                        else: # Should be rare for these structures
                            safe_print(f"  Entry {i+1}: {str(item_in_list_generic)[:200]}")
                elif isinstance(data_item_to_print, dict):
                     _print_dict_structure_cli(data_item_to_print, indent_level=1)
                else: # Should not happen for these keys
                    safe_print(f"  Data: {str(data_item_to_print)[:200]}")
            else:
                safe_print(f"  No {cli_title_str.lower()} found or data is empty.")

        _print_coff_symbols_cli(cli_pe_info_dict.get('coff_symbols_info', []), verbose_output_flag)
        _print_pefile_warnings_cli(cli_pe_info_dict.get('pefile_parsing_warnings', []))

        # --- Handle CLI-specific string extraction and search ---
        if arg_extract_strings_cli:
            safe_print(f"\n--- Extracted Strings (Min Length: {arg_min_str_len_cli}, Output Limit: {arg_strings_limit_cli}) ---")
            try:
                # Use the internal helper directly with the PE object's full data
                all_file_data_bytes = pe_obj_for_cli_analysis.__data__ if hasattr(pe_obj_for_cli_analysis, '__data__') else b''
                if not all_file_data_bytes:
                    safe_print("  Error: Cannot extract strings, PE file data is unavailable.")
                else:
                    extracted_strings_list_tuples = _extract_strings_from_data(all_file_data_bytes, arg_min_str_len_cli)
                    if not extracted_strings_list_tuples:
                        safe_print("  No strings found matching criteria.")
                    else:
                        for i, (offset_val, str_val) in enumerate(extracted_strings_list_tuples):
                            if i >= arg_strings_limit_cli:
                                safe_print(f"  ... (output limited to {arg_strings_limit_cli} strings, {len(extracted_strings_list_tuples) - i} more found)")
                                break
                            safe_print(f"  Offset: {hex(offset_val):<12} String: {str_val}")
            except Exception as e_str_extract_cli:
                safe_print(f"  Error during string extraction: {e_str_extract_cli}")
                logger.warning("CLI: Error during string extraction", exc_info=verbose_output_flag)

        if arg_search_strings_cli: # This is a list of strings to search for
            safe_print(f"\n--- Searched Strings Results (Output Limit Per Term: {arg_strings_limit_cli}) ---")
            try:
                all_file_data_bytes_search = pe_obj_for_cli_analysis.__data__ if hasattr(pe_obj_for_cli_analysis, '__data__') else b''
                if not all_file_data_bytes_search:
                     safe_print("  Error: Cannot search strings, PE file data is unavailable.")
                else:
                    search_results_dict_offsets = _search_specific_strings_in_data(all_file_data_bytes_search, arg_search_strings_cli)
                    found_any_terms_cli = False
                    for term_searched, offsets_list_int_found in search_results_dict_offsets.items():
                        if offsets_list_int_found:
                            found_any_terms_cli = True
                            safe_print(f"  Found string '{term_searched}' at offsets (limit {arg_strings_limit_cli} shown):")
                            for i, offset_val_found in enumerate(offsets_list_int_found):
                                if i >= arg_strings_limit_cli:
                                    safe_print(f"    ... (further {len(offsets_list_int_found) - i} occurrences of '{term_searched}' omitted)")
                                    break
                                safe_print(f"      - Offset: {hex(offset_val_found)}")
                        else:
                            safe_print(f"  String '{term_searched}' was not found in the file.")
                    if not found_any_terms_cli and arg_search_strings_cli: # Searched but found none
                         safe_print("  None of the specified search strings were found.")

            except Exception as e_search_cli:
                safe_print(f"  Error during specific string search: {e_search_cli}")
                logger.warning("CLI: Error during specific string search", exc_info=verbose_output_flag)

        # --- Handle CLI hex dump if requested ---
        if arg_hexdump_offset_cli is not None and arg_hexdump_length_cli is not None:
            safe_print(f"\n--- Hex Dump (Offset: {hex(arg_hexdump_offset_cli)}, Length: {arg_hexdump_length_cli} bytes, Max Lines: {arg_hexdump_lines_cli}) ---")
            try:
                file_data_for_dump = pe_obj_for_cli_analysis.__data__ if hasattr(pe_obj_for_cli_analysis, '__data__') else b''
                if not file_data_for_dump:
                    safe_print("  Error: Cannot perform hex dump, PE file data is unavailable.")
                else:
                    file_size_for_dump = len(file_data_for_dump)
                    if arg_hexdump_offset_cli >= file_size_for_dump:
                        safe_print("  Error: Start offset for hex dump is beyond the file size.")
                    else:
                        actual_dump_len = min(arg_hexdump_length_cli, file_size_for_dump - arg_hexdump_offset_cli)
                        if actual_dump_len <= 0:
                            safe_print("  Error: Calculated length for hex dump is zero or negative.")
                        else:
                            data_chunk_to_dump_cli = file_data_for_dump[arg_hexdump_offset_cli : arg_hexdump_offset_cli + actual_dump_len]
                            dump_lines_list_cli = _format_hex_dump_lines(data_chunk_to_dump_cli, start_address=arg_hexdump_offset_cli)
                            
                            if not dump_lines_list_cli:
                                safe_print("  No data to dump for the specified range (or range was empty after adjustments).")
                            else:
                                for i, line_str_dump in enumerate(dump_lines_list_cli):
                                    if i >= arg_hexdump_lines_cli:
                                        safe_print(f"  ... (hex dump output limited to {arg_hexdump_lines_cli} lines, {len(dump_lines_list_cli) - i} more available)")
                                        break
                                    safe_print(f"  {line_str_dump}")
            except IndexError: # Should be caught by offset/length checks, but as a safeguard
                 safe_print("  Error: Hex dump range is invalid or out of bounds for the file data.")
            except Exception as e_dump_cli:
                safe_print(f"  Error during hex dump: {e_dump_cli}")
                logger.warning("CLI: Error during hex dump", exc_info=verbose_output_flag)
                
        safe_print("\n[*] CLI Mode: Analysis complete.")

    # --- Exception Handling for CLI Mode PE Loading/Parsing ---
    except pefile.PEFormatError as e_pe_format_cli:
        safe_print(f"\n[!] CLI Error: Not a valid PE file or PE format error for '{filepath_to_analyze}': {e_pe_format_cli}")
        logger.error(f"CLI: PEFormatError for file '{filepath_to_analyze}': {e_pe_format_cli}", exc_info=verbose_output_flag)
        # No sys.exit here; main block will handle exit if this function raises
        raise # Re-raise for the main block to catch and exit gracefully
    except FileNotFoundError: # Should be caught by main, but good to have specific message if it reaches here
        safe_print(f"\n[!] CLI Error: Input file not found: {filepath_to_analyze}")
        logger.error(f"CLI: FileNotFoundError for file '{filepath_to_analyze}'")
        raise
    except Exception as e_load_cli: # Catch any other error during PE loading or main parsing
        safe_print(f"\n[!] CLI Error: An error occurred loading or parsing PE file '{filepath_to_analyze}': {type(e_load_cli).__name__} - {e_load_cli}")
        logger.error(f"CLI: Generic error loading/parsing PE file '{filepath_to_analyze}': {e_load_cli}", exc_info=verbose_output_flag)
        raise
    finally:
        # Ensure PE object is closed if it was successfully opened
        if pe_obj_for_cli_analysis:
            pe_obj_for_cli_analysis.close()
            if verbose_output_flag: logger.debug(f"CLI: Closed PE object for {filepath_to_analyze}")

# --- MCP Server Setup ---
# Initialize FastMCP instance (or MockMCP if SDK not available)
# The actual FastMCP object is created based on MCP_SDK_AVAILABLE flag,
# so this line effectively uses the mock if SDK is missing.
mcp_server = FastMCP("PEFileAnalyzerMCP_Refactored", 
                     description="MCP Server for PE file analysis. Pre-analyzes the --input-file at startup. Tools operate on this pre-loaded file.")
tool_decorator = mcp_server.tool() # Get the tool decorator

# --- MCP Tool Helper Decorator ---
def mcp_tool_requires_loaded_pe(func):
    """
    Decorator for MCP tools that require ANALYZED_PE_DATA and PE_OBJECT_FOR_MCP to be populated.
    Raises RuntimeError if the PE data is not loaded.
    """
    @functools.wraps(func)
    async def wrapper(ctx: Context, *args_wrapper, **kwargs_wrapper):
        if ANALYZED_PE_DATA is None or PE_OBJECT_FOR_MCP is None:
            message = (f"Tool '{func.__name__}' cannot operate: No PE file has been successfully pre-loaded "
                       "or its analysis data is unavailable. Ensure the server started correctly with a valid --input-file.")
            await ctx.error(message)
            logger.error(f"MCP Tool '{func.__name__}': {message}") # Server-side log
            raise RuntimeError(message) # This will result in an error response from MCP
        return await func(ctx, *args_wrapper, **kwargs_wrapper)
    return wrapper

# --- MCP Response Size Check Helper ---
async def _check_mcp_response_size(
    ctx: Context,
    data_to_return: Any,
    tool_name_for_log: str,
    limit_param_info_for_msg: Optional[str] = None
) -> Any:
    """
    Checks if the serialized size of data_to_return exceeds MAX_MCP_RESPONSE_SIZE_BYTES.
    If it does, logs an error via ctx, and raises a ValueError (which MCP should handle as a tool error).
    Otherwise, returns data_to_return.

    Args:
        ctx: The MCP Context object.
        data_to_return: The data payload intended for the MCP response.
        tool_name_for_log: Name of the tool, for logging.
        limit_param_info_for_msg: Optional string guiding the user on how to limit data,
                                  e.g., "your request parameters (using limits, offsets, or filters)".

    Returns:
        The original data_to_return if size is acceptable.

    Raises:
        ValueError: If the data size exceeds the configured limit, or if serialization fails.
    """
    try:
        # Attempt to serialize to JSON to estimate size.
        # Using ensure_ascii=False for a more accurate UTF-8 byte count.
        # Use default=str to handle non-serializable types like datetime, Path, etc., gracefully for size check.
        serialized_data_for_size_check = json.dumps(data_to_return, ensure_ascii=False, default=str)
        data_size_bytes_estimated = len(serialized_data_for_size_check.encode('utf-8'))

        if data_size_bytes_estimated > MAX_MCP_RESPONSE_SIZE_BYTES:
            param_guidance_str = limit_param_info_for_msg or \
                                 "your request parameters (e.g., using limits, offsets, or stricter filters)"
            error_message_for_user = (
                f"Response from tool '{tool_name_for_log}' (estimated {data_size_bytes_estimated // 1024}KB) "
                f"exceeds the maximum allowed server response size ({MAX_MCP_RESPONSE_SIZE_KB}KB). "
                f"Please request less data by adjusting {param_guidance_str}."
            )
            await ctx.error(error_message_for_user) # Send error to client via MCP context
            logger.warning(f"MCP Tool '{tool_name_for_log}': Response too large ({data_size_bytes_estimated} bytes). Client needs to adjust request.")
            raise ValueError(error_message_for_user) # Raise error to stop tool execution here
        
        return data_to_return # Return original data if size is OK
        
    except TypeError as e_json_serialize: # Handles non-JSON-serializable data if default=str isn't enough
        err_msg_json = f"Internal error in tool '{tool_name_for_log}': Could not serialize response data to check its size. Error: {e_json_serialize}"
        await ctx.error(err_msg_json)
        logger.error(f"MCP Tool '{tool_name_for_log}': Failed to serialize response for size check: {e_json_serialize}", exc_info=True)
        raise ValueError(err_msg_json) from e_json_serialize
    except Exception as e_other_size_check: # Catch any other unexpected errors during the size check
        err_msg_other = f"Internal error in tool '{tool_name_for_log}' while checking response size: {e_other_size_check}"
        await ctx.error(err_msg_other)
        logger.error(f"MCP Tool '{tool_name_for_log}': Unexpected error during response size check: {e_other_size_check}", exc_info=True)
        raise ValueError(err_msg_other) from e_other_size_check


# --- MCP Tools ---
@tool_decorator
@mcp_tool_requires_loaded_pe # Ensures ANALYZED_PE_DATA and its hashes are available
async def get_virustotal_report_for_loaded_file(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves a summary report from VirusTotal for the pre-loaded PE file using its hash.
    Requires the 'requests' library and a VirusTotal API key set in the VT_API_KEY environment variable.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing VirusTotal report summary or an error/status message.
        Includes hashes, detection statistics, and other metadata from VirusTotal.
    """
    tool_name = "get_virustotal_report_for_loaded_file"
    await ctx.info(f"MCP Tool '{tool_name}': Request for VirusTotal report for the loaded file.")

    # ANALYZED_PE_DATA is guaranteed by decorator, file_hashes should be there if parsing was complete
    file_hashes = ANALYZED_PE_DATA.get('file_hashes_calculated', {}) 
    main_hash_value: Optional[str] = None
    hash_type_used: Optional[str] = None

    # Prefer SHA256 for VT, then SHA1, then MD5
    if file_hashes.get('sha256'): main_hash_value, hash_type_used = file_hashes['sha256'], "sha256"
    elif file_hashes.get('sha1'): main_hash_value, hash_type_used = file_hashes['sha1'], "sha1"
    elif file_hashes.get('md5'): main_hash_value, hash_type_used = file_hashes['md5'], "md5"

    if not main_hash_value or not hash_type_used:
        msg = "No suitable hash (SHA256, SHA1, MD5) available in loaded PE data for VirusTotal query."
        await ctx.error(msg)
        return await _check_mcp_response_size(ctx, {"status": "error_no_hash", "message": msg}, tool_name)

    if not VT_API_KEY:
        msg = "VirusTotal API key (VT_API_KEY) is not configured in the server environment."
        await ctx.warning(msg) # Warning as it's a config issue, not a PE data issue
        return await _check_mcp_response_size(ctx, {"status": "api_key_missing", "message": msg, "query_hash": main_hash_value}, tool_name)

    if not REQUESTS_AVAILABLE: # Global flag
        msg = "'requests' library is not installed/available on the server, required for VirusTotal queries."
        await ctx.error(msg) # Error as tool cannot function
        return await _check_mcp_response_size(ctx, {"status": "dependency_missing", "library": "requests", "message": msg}, tool_name)

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    api_url_to_query = f"{VT_API_URL_FILE_REPORT}{main_hash_value}"
    
    response_payload_to_client: Dict[str, Any] = { # Default error/info structure
        "status": "pending_vt_query",
        "query_hash_type": hash_type_used,
        "query_hash": main_hash_value,
        "locally_calculated_ssdeep": file_hashes.get('ssdeep'), # Include local ssdeep for comparison
    }

    try:
        await ctx.info(f"MCP Tool '{tool_name}': Querying VirusTotal API: {api_url_to_query}")
        # Use asyncio.to_thread for blocking 'requests' call
        http_response = await asyncio.to_thread(requests.get, api_url_to_query, headers=headers, timeout=25) # Slightly longer timeout

        if http_response.status_code == 200:
            vt_json_response = http_response.json()
            vt_data_attributes = vt_json_response.get("data", {}).get("attributes", {})

            # Extract key information from VT response
            vt_summary_for_client = {
                "report_gui_link": f"https://www.virustotal.com/gui/file/{main_hash_value}",
                "hashes_from_vt": {
                    "md5": vt_data_attributes.get("md5"), "sha1": vt_data_attributes.get("sha1"),
                    "sha256": vt_data_attributes.get("sha256"), "ssdeep": vt_data_attributes.get("ssdeep"),
                },
                "detection_statistics": vt_data_attributes.get("last_analysis_stats"),
                "last_analysis_date_iso_utc": datetime.datetime.fromtimestamp(vt_data_attributes.get("last_analysis_date"), datetime.timezone.utc).isoformat() if vt_data_attributes.get("last_analysis_date") else None,
                "first_submission_date_iso_utc": datetime.datetime.fromtimestamp(vt_data_attributes.get("first_submission_date"), datetime.timezone.utc).isoformat() if vt_data_attributes.get("first_submission_date") else None,
                "reputation_score": vt_data_attributes.get("reputation"),
                "tags_from_vt": vt_data_attributes.get("tags", []),
                "suggested_threat_label": vt_data_attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "trid_results": vt_data_attributes.get("trid", []),
                "meaningful_name_vt": vt_data_attributes.get("meaningful_name"),
                "file_size_vt": vt_data_attributes.get("size"),
                "type_description_vt": vt_data_attributes.get("type_description"),
                "type_tag_vt": vt_data_attributes.get("type_tag"),
                "magic_vt": vt_data_attributes.get("magic")
            }
            response_payload_to_client["status"] = "success_vt_report_retrieved"
            response_payload_to_client["message"] = "VirusTotal report summary retrieved successfully."
            response_payload_to_client["virustotal_report_summary"] = vt_summary_for_client
            await ctx.info(f"MCP Tool '{tool_name}': Successfully retrieved VirusTotal report for {main_hash_value}")

        elif http_response.status_code == 404: # Hash not found on VT
            response_payload_to_client["status"] = "vt_hash_not_found"
            response_payload_to_client["message"] = f"Hash {main_hash_value} was not found on VirusTotal."
            await ctx.info(f"MCP Tool '{tool_name}': Hash {main_hash_value} not found on VirusTotal.")
        # Handle other common HTTP errors from VT
        elif http_response.status_code == 401: # Authentication error
            response_payload_to_client["status"] = "error_vt_authentication"
            response_payload_to_client["message"] = "VirusTotal API authentication failed. Check server's VT_API_KEY."
            await ctx.error(f"MCP Tool '{tool_name}': VirusTotal API authentication failed (401).")
        elif http_response.status_code == 429: # Rate limit
            response_payload_to_client["status"] = "error_vt_rate_limit"
            response_payload_to_client["message"] = "VirusTotal API rate limit exceeded. Please try again later."
            await ctx.warning(f"MCP Tool '{tool_name}': VirusTotal API rate limit exceeded (429).")
        else: # Other API errors
            response_payload_to_client["status"] = "error_vt_api_other"
            response_payload_to_client["message"] = f"VirusTotal API returned an error. Status: {http_response.status_code}. Response: {http_response.text[:250]}" # Limit response text
            await ctx.error(f"MCP Tool '{tool_name}': VirusTotal API error for {main_hash_value}: {http_response.status_code} - {http_response.text[:100]}")

    except requests.exceptions.Timeout:
        response_payload_to_client["status"] = "error_vt_request_timeout"
        response_payload_to_client["message"] = "Request to VirusTotal API timed out."
        await ctx.error(f"MCP Tool '{tool_name}': VirusTotal API request timed out for {main_hash_value}.")
    except requests.exceptions.RequestException as e_req_vt: # Other requests library errors
        response_payload_to_client["status"] = "error_vt_request_general"
        response_payload_to_client["message"] = f"Error during VirusTotal API request: {str(e_req_vt)}"
        await ctx.error(f"MCP Tool '{tool_name}': VirusTotal API request error for {main_hash_value}: {e_req_vt}")
    except Exception as e_vt_tool: # Catch-all for unexpected errors within this tool
        response_payload_to_client["status"] = "error_tool_unexpected"
        response_payload_to_client["message"] = f"An unexpected error occurred in '{tool_name}': {str(e_vt_tool)}"
        logger.error(f"MCP Tool '{tool_name}': Unexpected error for {main_hash_value}: {e_vt_tool}", exc_info=True)
        await ctx.error(f"MCP Tool '{tool_name}': Unexpected error: {e_vt_tool}")

    # Check size before returning
    limit_info_for_msg = "This tool returns a fixed structure; if too large, it's a server configuration issue or VT returned excessive data."
    return await _check_mcp_response_size(ctx, response_payload_to_client, tool_name, limit_info_for_msg)
    
@tool_decorator
async def reanalyze_loaded_pe_file(
    ctx: Context,
    peid_db_path_override: Optional[str] = None,
    yara_rules_path_override: Optional[str] = None,
    capa_rules_dir_override: Optional[str] = None,
    capa_sigs_dir_override: Optional[str] = None,
    analyses_to_skip_list: Optional[List[str]] = None, 
    skip_capa_analysis_flag: Optional[bool] = None,
    mcp_reanalysis_verbose_log: bool = False, # Renamed for clarity
    peid_skip_full_scan_flag: bool = False, # Renamed
    peid_use_all_sigs_heuristically_flag: bool = False # Renamed
) -> Dict[str, Any]:
    """
    Re-triggers a full or partial analysis of the PE file pre-loaded at server startup.
    Allows overriding paths for rules/DBs and skipping specific analyses.
    The global analysis results (ANALYZED_PE_DATA, PE_OBJECT_FOR_MCP) are updated.

    Args:
        ctx: The MCP Context object.
        peid_db_path_override: (Optional) Override path to PEiD userdb.txt.
        yara_rules_path_override: (Optional) Override path to YARA rule file/directory.
        capa_rules_dir_override: (Optional) Override path to capa rule directory.
        capa_sigs_dir_override: (Optional) Override path to capa library ID signature files.
        analyses_to_skip_list: (Optional) List of analyses to skip (e.g., ["peid", "yara", "capa"]).
        skip_capa_analysis_flag: (Optional) If True, capa analysis is skipped (overrides list for capa).
        mcp_reanalysis_verbose_log: (bool) Enables detailed server-side logging for this re-analysis.
        peid_skip_full_scan_flag: (bool) If True (and PEiD not skipped), PEiD scan is entry point only.
        peid_use_all_sigs_heuristically_flag: (bool) For full PEiD scan, if True, all sigs used heuristically.

    Returns:
        A dictionary indicating status, e.g., {"status": "success", "message": "File re-analyzed.", "filepath": "..."}
    Raises:
        RuntimeError: If no PE file pre-loaded, or if re-analysis encounters a critical error.
        asyncio.CancelledError: If the underlying analysis task is cancelled by MCP.
    """
    global ANALYZED_PE_FILE_PATH, ANALYZED_PE_DATA, PE_OBJECT_FOR_MCP # These will be updated

    tool_name = "reanalyze_loaded_pe_file"
    await ctx.info(f"MCP Tool '{tool_name}': Request to re-analyze pre-loaded PE.")

    if ANALYZED_PE_FILE_PATH is None or not Path(ANALYZED_PE_FILE_PATH).exists():
        msg = "No PE file was successfully pre-loaded at server startup, or its path is now invalid. Cannot re-analyze."
        await ctx.error(msg)
        logger.error(f"MCP Tool '{tool_name}': {msg}")
        raise RuntimeError(msg)

    await ctx.info(f"MCP Tool '{tool_name}': Current pre-loaded file: {ANALYZED_PE_FILE_PATH}")

    # Determine final list of analyses to skip
    current_analyses_to_skip = []
    if analyses_to_skip_list:
        current_analyses_to_skip = [analysis.lower().strip() for analysis in analyses_to_skip_list]
    
    if skip_capa_analysis_flag is True and "capa" not in current_analyses_to_skip:
        current_analyses_to_skip.append("capa")
        await ctx.info(f"MCP Tool '{tool_name}': Capa analysis will be skipped due to 'skip_capa_analysis_flag=True'.")
    elif skip_capa_analysis_flag is False and "capa" in current_analyses_to_skip:
        current_analyses_to_skip.remove("capa")
        await ctx.info(f"MCP Tool '{tool_name}': Capa analysis will be performed as 'skip_capa_analysis_flag=False' (overriding list).")
            
    if current_analyses_to_skip:
        await ctx.info(f"MCP Tool '{tool_name}': Final list of analyses to skip: {current_analyses_to_skip}")

    # Resolve paths: Use overrides if provided and valid, otherwise use script defaults or None.
    # The _parse_pe_to_dict function and its helpers (like ensure_peid_db_exists) will handle
    # defaults if these resolved paths are None or invalid where a default is possible.
    
    # Helper to resolve and log path overrides
    def _resolve_override_path(override_path_str: Optional[str], path_description: str) -> Optional[str]:
        if override_path_str:
            resolved = str(Path(override_path_str).resolve())
            await ctx.info(f"MCP Tool '{tool_name}': Using override for {path_description}: {resolved}")
            return resolved
        await ctx.info(f"MCP Tool '{tool_name}': No override for {path_description}, will use server defaults or None.")
        return None # Let downstream functions handle None (use default or skip)

    final_peid_db_path = _resolve_override_path(peid_db_path_override, "PEiD DB path") or str(DEFAULT_PEID_DB_PATH) # PEiD DB has a hard default
    final_yara_rules_path = await _resolve_override_path(yara_rules_path_override, "YARA rules path")
    final_capa_rules_dir = await _resolve_override_path(capa_rules_dir_override, "Capa rules directory")
    final_capa_sigs_dir = await _resolve_override_path(capa_sigs_dir_override, "Capa signatures directory")


    # --- Perform re-analysis in a separate thread to avoid blocking asyncio event loop ---
    def perform_threaded_reanalysis():
        temp_pe_obj_for_reanalysis = None # For this thread's PE object
        try:
            # Always re-open the PE file from its path for a fresh, thread-isolated object.
            # This is crucial if the global PE_OBJECT_FOR_MCP might have been closed or modified.
            logger.info(f"Threaded Re-analysis: Opening PE file: {ANALYZED_PE_FILE_PATH}")
            temp_pe_obj_for_reanalysis = pefile.PE(ANALYZED_PE_FILE_PATH, fast_load=False) 
            
            logger.info(f"Threaded Re-analysis: Calling _parse_pe_to_dict for {ANALYZED_PE_FILE_PATH}")
            newly_parsed_data = _parse_pe_to_dict(
                temp_pe_obj_for_reanalysis, ANALYZED_PE_FILE_PATH, 
                final_peid_db_path, final_yara_rules_path,
                final_capa_rules_dir, final_capa_sigs_dir,
                mcp_reanalysis_verbose_log, # Use the tool's verbose flag for parsing logs
                peid_skip_full_scan_flag, 
                peid_use_all_sigs_heuristically_flag,
                analyses_to_skip=current_analyses_to_skip
            )
            logger.info(f"Threaded Re-analysis: _parse_pe_to_dict completed for {ANALYZED_PE_FILE_PATH}")
            # Return both the new PE object and the parsed data.
            # The calling async tool method will handle updating globals and closing the old global PE object.
            return temp_pe_obj_for_reanalysis, newly_parsed_data
        
        except Exception as e_thread_reparse: 
            # If an error occurs within this thread, close the temporary PE object if it was opened.
            if temp_pe_obj_for_reanalysis:
                try: temp_pe_obj_for_reanalysis.close()
                except Exception as e_close_in_thread_err: logger.error(f"Threaded Re-analysis: Error closing temp PE object on error: {e_close_in_thread_err}")
            
            # Re-raise the exception to be caught by the outer handler in the async tool method.
            logger.error(f"Threaded Re-analysis: Error during re-analysis of {ANALYZED_PE_FILE_PATH}: {e_thread_reparse}", exc_info=mcp_reanalysis_verbose_log)
            raise # Propagate error to the asyncio task

    try:
        # Run the blocking analysis in a thread. This can be cancelled if the MCP task is cancelled.
        new_pe_obj_from_thread_reanalysis, new_data_from_thread_reanalysis = await asyncio.to_thread(perform_threaded_reanalysis)
        
        # --- If re-analysis successful and not cancelled, update global state ---
        # Close the old global PE_OBJECT_FOR_MCP before replacing it to free resources.
        if PE_OBJECT_FOR_MCP: 
            try: PE_OBJECT_FOR_MCP.close()
            except Exception as e_close_old_global_pe: logger.warning(f"MCP Tool '{tool_name}': Error closing old global PE object: {e_close_old_global_pe}")
        
        PE_OBJECT_FOR_MCP = new_pe_obj_from_thread_reanalysis # Store the new PE object globally
        ANALYZED_PE_DATA = new_data_from_thread_reanalysis   # Update the global analysis data

        success_msg = f"File '{ANALYZED_PE_FILE_PATH}' re-analyzed successfully."
        if current_analyses_to_skip: success_msg += f" (Skipped analyses: {', '.join(current_analyses_to_skip)})"
        await ctx.info(f"MCP Tool '{tool_name}': {success_msg}")
        
        # Return a simple success message. The main data is in globals.
        # This response itself is small.
        return {"status":"success", "message": success_msg, "filepath": ANALYZED_PE_FILE_PATH}

    except asyncio.CancelledError: 
        # This occurs if the asyncio.Task running this tool is cancelled by MCP framework.
        # The `perform_threaded_reanalysis`'s finally block (if it had one) or error handling
        # should manage its temporary PE object.
        # Global state (PE_OBJECT_FOR_MCP, ANALYZED_PE_DATA) should remain from the *previous* load.
        msg_cancel = f"Re-analysis task for {ANALYZED_PE_FILE_PATH} was cancelled by MCP framework."
        await ctx.warning(msg_cancel)
        logger.info(f"MCP Tool '{tool_name}': {msg_cancel}. Global PE data remains from previous state.")
        raise # Re-raise for MCP framework to handle (typically means no response sent to client)
    
    except Exception as e_reanalyze_outer: # Catch errors from perform_threaded_reanalysis or other issues
        err_msg_reanalyze = f"Error re-analyzing PE '{ANALYZED_PE_FILE_PATH}': {type(e_reanalyze_outer).__name__} - {str(e_reanalyze_outer)}"
        await ctx.error(err_msg_reanalyze)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_reanalyze}", exc_info=mcp_reanalysis_verbose_log)
        # Global state remains from before this failed re-analysis attempt.
        raise RuntimeError(f"Failed to re-analyze PE file '{ANALYZED_PE_FILE_PATH}': {str(e_reanalyze_outer)}") from e_reanalyze_outer


@tool_decorator
@mcp_tool_requires_loaded_pe
async def get_analyzed_file_summary(ctx: Context, limit_top_level_keys: int) -> Dict[str, Any]:
    """
    Retrieves a high-level summary of the pre-loaded and analyzed PE file.

    Args:
        ctx: The MCP Context object.
        limit_top_level_keys: (int) Mandatory. Limits the number of top-level key-value pairs
                                from the generated summary to return. Must be positive.

    Returns:
        A dictionary containing summary information, limited by `limit_top_level_keys`.
    Raises:
        ValueError: If `limit_top_level_keys` is not a positive integer, or if response size limit hit.
    """
    tool_name = "get_analyzed_file_summary"
    await ctx.info(f"MCP Tool '{tool_name}': Request for analyzed file summary. Key limit: {limit_top_level_keys}")
    
    if not (isinstance(limit_top_level_keys, int) and limit_top_level_keys > 0):
        raise ValueError("Parameter 'limit_top_level_keys' must be a positive integer.")
        
    # ANALYZED_PE_DATA is guaranteed by the decorator.
    # Construct a summary on the fly from ANALYZED_PE_DATA
    full_summary_dict = {
        "filepath_analyzed": ANALYZED_PE_FILE_PATH,
        "pefile_version_at_analysis": PEFILE_VERSION_USED,
        "parsing_timestamp_utc_at_analysis": ANALYZED_PE_DATA.get("parsing_timestamp_utc"),
        "pe_architecture_type": ANALYZED_PE_DATA.get("pe_architecture_string", "Unknown"),
        
        "dos_header_present": 'dos_header_info' in ANALYZED_PE_DATA and ANALYZED_PE_DATA['dos_header_info'] is not None and "error" not in ANALYZED_PE_DATA['dos_header_info'],
        "nt_headers_present": 'nt_headers_info' in ANALYZED_PE_DATA and ANALYZED_PE_DATA['nt_headers_info'] is not None and "error" not in ANALYZED_PE_DATA['nt_headers_info'],
        
        "section_count": len(ANALYZED_PE_DATA.get('sections_info', [])),
        "import_dll_count": len(ANALYZED_PE_DATA.get('imports_info', [])),
        "export_symbol_count": len(ANALYZED_PE_DATA.get('exports_info', {}).get('exported_symbols', [])),
        
        "peid_status": ANALYZED_PE_DATA.get('peid_scan_analysis', {}).get('status', "Not run/Skipped"),
        "peid_ep_match_count": len(ANALYZED_PE_DATA.get('peid_scan_analysis', {}).get('ep_only_matches', [])),
        "peid_heuristic_match_count": len(ANALYZED_PE_DATA.get('peid_scan_analysis', {}).get('heuristic_matches', [])),
        
        "yara_status": ANALYZED_PE_DATA.get('yara_scan_analysis', [{}])[0].get('status', "Not run/Skipped") if ANALYZED_PE_DATA.get('yara_scan_analysis') and isinstance(ANALYZED_PE_DATA.get('yara_scan_analysis'), list) and ANALYZED_PE_DATA.get('yara_scan_analysis')[0] else "Not run/Skipped",
        "yara_actual_match_count": len([m for m in ANALYZED_PE_DATA.get('yara_scan_analysis', []) if isinstance(m, dict) and "rule_name" in m]), # Count actual rule matches
        
        "capa_status": ANALYZED_PE_DATA.get('capa_rules_analysis', {}).get('status', "Not run/Skipped"),
        "capa_detected_capability_count": len(ANALYZED_PE_DATA.get('capa_rules_analysis', {}).get('results', {}).get('rules', {})) if ANALYZED_PE_DATA.get('capa_rules_analysis', {}).get('status', '').startswith("Analysis complete") else 0,
        
        "is_digitally_signed": ANALYZED_PE_DATA.get('digital_signature_info', {}).get('is_signed_according_to_directory', False),
        "rich_header_present": ANALYZED_PE_DATA.get('rich_header_info') is not None,
        "overlay_present": ANALYZED_PE_DATA.get('overlay_data_info') is not None,
    }
    await ctx.info(f"MCP Tool '{tool_name}': Summary for {ANALYZED_PE_FILE_PATH} generated with {len(full_summary_dict)} total keys.")
    
    # Apply the limit to the number of top-level keys in the summary itself
    limited_summary_to_send = dict(list(full_summary_dict.items())[:limit_top_level_keys])
    
    limit_info_str = "the 'limit_top_level_keys' parameter"
    return await _check_mcp_response_size(ctx, limited_summary_to_send, tool_name, limit_info_str)


@tool_decorator
@mcp_tool_requires_loaded_pe
async def get_full_analysis_results(ctx: Context, limit_top_level_keys: int) -> Dict[str, Any]:
    """
    Retrieves the complete analysis results dictionary for the pre-loaded PE file,
    limited by the number of top-level keys specified.

    Args:
        ctx: The MCP Context object.
        limit_top_level_keys: (int) Mandatory. Limits the number of top-level key-value pairs
                                from the full analysis dictionary to return. Must be positive.

    Returns:
        A potentially large dictionary containing PE analysis data, limited by `limit_top_level_keys`.
    Raises:
        ValueError: If `limit_top_level_keys` is not a positive integer, or if response size limit hit.
    """
    tool_name = "get_full_analysis_results"
    await ctx.info(f"MCP Tool '{tool_name}': Request for full PE analysis results. Key limit: {limit_top_level_keys}")

    if not (isinstance(limit_top_level_keys, int) and limit_top_level_keys > 0):
        raise ValueError("Parameter 'limit_top_level_keys' must be a positive integer.")

    # ANALYZED_PE_DATA is guaranteed by the decorator.
    # Apply the limit to the number of top-level keys from the main ANALYZED_PE_DATA dictionary
    data_to_send_limited_keys = dict(list(ANALYZED_PE_DATA.items())[:limit_top_level_keys])
    
    limit_info_str = ("the 'limit_top_level_keys' parameter (to request fewer top-level data categories), "
                      "or use more specific data retrieval tools (e.g., get_sections_info, get_imports_info) "
                      "which offer finer-grained limiting and pagination for their respective data.")
    return await _check_mcp_response_size(ctx, data_to_send_limited_keys, tool_name, limit_info_str)


# --- Dynamically Create MCP Tools for Specific Data Keys ---
# This creates get_X_info tools for many keys in ANALYZED_PE_DATA
def _create_mcp_tool_for_specific_data_key(data_key_name: str, tool_doc_description: str):
    """
    Factory function to create an MCP tool that retrieves a specific top-level key
    from the ANALYZED_PE_DATA dictionary, with pagination for list data.
    """
    @mcp_tool_requires_loaded_pe # Apply the PE loaded check decorator
    async def _generated_tool_func(ctx: Context, 
                                   limit_items: int,  # Max items if data is a list/dict
                                   offset_items: Optional[int] = 0 # Offset if data is a list
                                  ) -> Any: # Return type depends on the data_key_name
        tool_name_generated = f"get_{data_key_name}_info"
        await ctx.info(f"MCP Tool '{tool_name_generated}': Request for '{data_key_name}'. Item Limit: {limit_items}, Item Offset: {offset_items}")

        if not (isinstance(limit_items, int) and limit_items > 0):
            raise ValueError(f"Parameter 'limit_items' for '{tool_name_generated}' must be a positive integer.")
        
        current_item_offset = 0
        if offset_items is not None:
            if not (isinstance(offset_items, int) and offset_items >= 0):
                await ctx.warning(f"MCP Tool '{tool_name_generated}': Invalid 'offset_items' value '{offset_items}'. Using offset 0.")
            else:
                current_item_offset = offset_items
        
        # ANALYZED_PE_DATA is guaranteed by the decorator.
        original_data_for_key = ANALYZED_PE_DATA.get(data_key_name)

        if original_data_for_key is None:
            await ctx.warning(f"MCP Tool '{tool_name_generated}': Data for key '{data_key_name}' not found in analyzed results. Returning empty structure or None.")
            # For None or empty, size check is trivial but consistent.
            empty_return = [] if data_key_name.endswith("_info") or data_key_name.endswith("_list") else {} # Guess appropriate empty type
            return await _check_mcp_response_size(ctx, empty_return, tool_name_generated)

        # Apply offset and limit based on data type
        data_to_send_paginated: Any
        if isinstance(original_data_for_key, list):
            # Apply offset first for lists
            data_after_offset = original_data_for_key[current_item_offset:] if current_item_offset > 0 else original_data_for_key
            data_to_send_paginated = data_after_offset[:limit_items] # Then apply limit
        elif isinstance(original_data_for_key, dict):
            # For dicts, offset usually doesn't apply directly to top-level keys.
            # Limit will take the first 'limit_items' key-value pairs.
            if current_item_offset > 0:
                 await ctx.info(f"MCP Tool '{tool_name_generated}': 'offset_items' is {current_item_offset} but data for '{data_key_name}' is a dictionary. Offset will be ignored for top-level keys.")
            try:
                data_to_send_paginated = dict(list(original_data_for_key.items())[:limit_items])
            except Exception as e_dict_limit_tool: # Should not happen with simple dict slicing
                await ctx.warning(f"MCP Tool '{tool_name_generated}': Could not apply item limit for dictionary key '{data_key_name}': {e_dict_limit_tool}. Will check size of full data for this key.")
                data_to_send_paginated = original_data_for_key # Send full dict if limiting failed; size check will catch if too big
        else: # For other data types (e.g., string, int, bool, simple dicts not needing pagination)
            await ctx.info(f"MCP Tool '{tool_name_generated}': Data for key '{data_key_name}' is type '{type(original_data_for_key).__name__}'. 'limit_items' and 'offset_items' acknowledged but not directly used for slicing this type.")
            data_to_send_paginated = original_data_for_key # Return the whole item

        limit_info_str_tool = f"the 'limit_items' or 'offset_items' parameters for data key '{data_key_name}'"
        return await _check_mcp_response_size(ctx, data_to_send_paginated, tool_name_generated, limit_info_str_tool)

    _generated_tool_func.__name__ = f"get_{data_key_name}_info" # Set dynamic name for MCP registration
    # Construct docstring dynamically
    doc = f"""Retrieves the '{data_key_name}' portion of the PE analysis results for the pre-loaded file.

Prerequisites:
- A PE file must have been successfully pre-loaded at server startup.

Args:
    ctx: The MCP Context object.
    limit_items: (int) Mandatory. Limits the number of items returned. Must be a positive integer.
                 For lists, it's the number of elements. For dictionaries, it's the number of top-level key-value pairs.
                 For other types, it's acknowledged but may not directly slice the data.
    offset_items: (Optional[int], default 0) Specifies the starting index for lists. Ignored for non-list types.

Returns:
    The data associated with '{data_key_name}'. Structure depends on the key:
    - {tool_doc_description}
    The return type is typically a dictionary, a list, or a primitive type.

Raises:
    RuntimeError: If no PE file is currently loaded.
    ValueError: If `limit_items` is not a positive integer, or if the response size exceeds the server limit.
"""
    _generated_tool_func.__doc__ = doc
    return tool_decorator(_generated_tool_func) # Apply the main MCP tool decorator

# Define which keys from ANALYZED_PE_DATA should have dedicated MCP tools
# Key in ANALYZED_PE_DATA -> User-friendly description for the tool's docstring
KEYS_FOR_DEDICATED_MCP_TOOLS = {
    "file_hashes_calculated": "Cryptographic hashes (MD5, SHA1, SHA256, ssdeep) for the entire loaded PE file. Output is a dictionary.",
    "dos_header_info": "Detailed breakdown of the DOS_HEADER structure from the PE file. Output is a dictionary (pefile dump_dict format).",
    "nt_headers_info": "Detailed breakdown of NT_HEADERS (Signature, FileHeader, OptionalHeader). Output is a dictionary.",
    "data_directories_info": "Information on Data Directories (import, export, etc.), including RVAs and sizes. Output is a list of dictionaries.",
    "sections_info": "Detailed information for each PE section (name, RVA, size, characteristics, entropy, hashes). Output is a list of dictionaries.",
    "imports_info": "List of imported DLLs and their symbols (functions/ordinals). Output is a list of dictionaries.",
    "exports_info": "Information on exported symbols, including name, RVA, ordinal, and forwarders. Output is a dictionary.",
    "resources_summary_info": "Summary list of resources (type, ID/name, language, RVA, size). Output is a list of dictionaries.",
    "version_info_parsed": "Version information from the PE's version resource. Output is a dictionary.",
    "debug_info_parsed": "Details from the debug directory (e.g., PDB paths). Output is a list of dictionaries.",
    "digital_signature_info": "Authenticode digital signature details (certs, validation status). Output is a dictionary.",
    "peid_scan_analysis": "PEiD-like signature scan results (packer/compiler detection). Output is a dictionary.",
    "yara_scan_analysis": "YARA scan results (matched rules, tags, meta, strings). Output is a list of dictionaries.",
    # Capa results are handled by more specific tools below due to their complexity.
    "rich_header_info": "Decoded Microsoft Rich Header information. Output is a dictionary or None.",
    "delay_load_imports_info": "Delay-loaded imported DLLs and symbols. Output is a list of dictionaries.",
    "tls_info_parsed": "Thread Local Storage (TLS) directory details, including callbacks. Output is a dictionary or None.",
    "load_config_info": "Load Configuration directory details (e.g., Guard Flags). Output is a dictionary or None.",
    "com_descriptor_info": ".NET COM Descriptor (Cor20Header) if present. Output is a dictionary or None.",
    "overlay_data_info": "Appended overlay data information (offset, size, hashes). Output is a dictionary or None.",
    "base_relocations_info": "Base relocation entries. Output is a list of dictionaries.",
    "bound_imports_info": "Bound import directory entries. Output is a list of dictionaries.",
    "exception_data_info": "Exception directory entries (e.g., x64 RUNTIME_FUNCTION). Output is a list of dictionaries.",
    "coff_symbols_info": "COFF symbol table entries, including auxiliary symbols. Output is a list of dictionaries.",
    "checksum_verification_results": "PE file checksum verification against Optional Header. Output is a dictionary.",
    "pefile_parsing_warnings": "Warnings generated by 'pefile' library during parsing. Output is a list of strings."
}
# Create the tools dynamically
for data_key, doc_desc in KEYS_FOR_DEDICATED_MCP_TOOLS.items():
    # The created tool function will be registered with MCP server via `tool_decorator`
    # and assigned to a global variable (e.g., get_sections_info) by Python.
    globals()[f"get_{data_key}_info"] = _create_mcp_tool_for_specific_data_key(data_key, doc_desc)


# --- More Specialized MCP Tools (e.g., for Capa, Strings, Hex Dump, Deobfuscation) ---

@tool_decorator
@mcp_tool_requires_loaded_pe # Ensures ANALYZED_PE_DATA and capa_rules_analysis part exists if run
async def get_capa_analysis_overview(ctx: Context, # Renamed from get_capa_analysis_info
                                 limit_rules_on_page: int, 
                                 offset_rules: Optional[int] = 0,
                                 filter_by_rule_name_substring: Optional[str] = None,
                                 filter_by_namespace_exact: Optional[str] = None,
                                 filter_by_attck_id_substring: Optional[str] = None,
                                 filter_by_mbc_id_substring: Optional[str] = None,
                                 # fields_to_include_per_rule: Optional[List[str]] = None, # Simplified: summary is fixed for now
                                 retrieve_report_metadata_only: bool = False,
                                 source_text_truncate_length: Optional[int] = None
                                 ) -> Dict[str, Any]:
    """
    Retrieves an overview of Capa capability rules from the pre-loaded analysis,
    with filtering and pagination. For each rule, 'matches' are summarized by a count of unique addresses.
    Use 'get_capa_rule_match_details' for detailed match info of a specific rule.

    Args:
        ctx: The MCP Context object.
        limit_rules_on_page: (int) Max capability rules to return in this page. Must be positive.
        offset_rules: (Optional[int]) Starting index for rule pagination. Defaults to 0.
        filter_by_rule_name_substring: (Optional[str]) Filter rules by name/ID (substring, case-insensitive).
        filter_by_namespace_exact: (Optional[str]) Filter rules by namespace (exact match, case-insensitive).
        filter_by_attck_id_substring: (Optional[str]) Filter rules by ATT&CK ID or tactic name (substring, case-insensitive).
        filter_by_mbc_id_substring: (Optional[str]) Filter rules by MBC ID or objective/behavior name (substring, case-insensitive).
        retrieve_report_metadata_only: (bool) If True, returns only the top-level 'meta' section of the Capa report (trimmed).
        source_text_truncate_length: (Optional[int]) If provided and positive, truncates the 'source' text of each rule.

    Returns:
        A dictionary containing:
        - "filtered_rules_summary": (Dict[str, Dict]) A dictionary of rule summaries, keyed by rule ID.
                                     Each summary includes 'meta', 'source' (possibly truncated), and 'match_address_count'.
        - "pagination_info": (Dict) Details about pagination (offset, limit, current count, total after filter).
        - "capa_report_metadata": (Dict) The 'meta' section from the Capa report (trimmed).
        - "error_message": (Optional[str]) If an error occurred.
    Raises:
        RuntimeError: If no Capa analysis data is found in the loaded PE data.
        ValueError: For invalid parameter values, or if the response size exceeds the server limit.
    """
    tool_name = "get_capa_analysis_overview"
    await ctx.info(f"MCP Tool '{tool_name}': Request. RuleLimit: {limit_rules_on_page}, RuleOffset: {offset_rules}, "
                   f"Filters: Name='{filter_by_rule_name_substring}', NS='{filter_by_namespace_exact}', "
                   f"ATT&CK='{filter_by_attck_id_substring}', MBC='{filter_by_mbc_id_substring}'. "
                   f"MetaOnly: {retrieve_report_metadata_only}, SrcTrunc: {source_text_truncate_length}")

    if not (isinstance(limit_rules_on_page, int) and limit_rules_on_page > 0):
        raise ValueError("Parameter 'limit_rules_on_page' must be a positive integer.")
    if source_text_truncate_length is not None and not (isinstance(source_text_truncate_length, int) and source_text_truncate_length >= 0):
        raise ValueError("Parameter 'source_text_truncate_length' must be a non-negative integer if provided.")
    
    current_rule_offset = 0
    if offset_rules is not None:
        if not (isinstance(offset_rules, int) and offset_rules >= 0):
            await ctx.warning(f"MCP Tool '{tool_name}': Invalid 'offset_rules' ({offset_rules}), using 0.")
        else:
            current_rule_offset = offset_rules

    # ANALYZED_PE_DATA is guaranteed by decorator. Check for 'capa_rules_analysis' specifically.
    capa_analysis_block = ANALYZED_PE_DATA.get('capa_rules_analysis', {})
    capa_full_report_results = capa_analysis_block.get('results') # This is the dict from capa's ResultDocument
    capa_run_status = capa_analysis_block.get("status", "Unknown")
    
    # Prepare pagination info structure, to be filled
    pagination_details = {
        'offset_rules_applied': current_rule_offset, 
        'limit_rules_requested': limit_rules_on_page, 
        'rules_on_current_page': 0,
        'total_rules_after_filtering': 0, 
        'total_capabilities_in_original_report': 0
    }
    
    # Process and trim capa report metadata (even if errors or no rules)
    original_report_meta = capa_full_report_results.get('meta', {}) if capa_full_report_results else {}
    trimmed_report_meta_for_client = copy.deepcopy(original_report_meta)
    if 'analysis' in trimmed_report_meta_for_client and isinstance(trimmed_report_meta_for_client['analysis'], dict):
        # Remove potentially large or less relevant fields from 'analysis' metadata for overview
        analysis_section_meta = trimmed_report_meta_for_client['analysis']
        for field_to_trim in ['layout', 'feature_counts', 'library_functions', 'function_symbols']: # Add more if needed
            if field_to_trim in analysis_section_meta:
                del analysis_section_meta[field_to_trim]

    # Handle cases where Capa didn't run or had issues
    if capa_run_status == "Skipped by user request" or capa_run_status.startswith("Skipped -"):
        msg = f"Capa analysis was skipped (Status: {capa_run_status})."
        await ctx.info(f"MCP Tool '{tool_name}': {msg}")
        data_to_send = {"error_message": msg, "filtered_rules_summary": {}, 
                        "pagination_info": pagination_details, "capa_report_metadata": trimmed_report_meta_for_client}
        return await _check_mcp_response_size(ctx, data_to_send, tool_name)
        
    if not capa_run_status.startswith("Analysis complete") or not capa_full_report_results:
        err_msg = f"Capa analysis not complete or results missing. Status: {capa_run_status}. Error: {capa_analysis_block.get('error')}"
        await ctx.warning(f"MCP Tool '{tool_name}': {err_msg}")
        data_to_send = {"error_message": err_msg, "filtered_rules_summary": {},
                        "pagination_info": pagination_details, "capa_report_metadata": trimmed_report_meta_for_client}
        return await _check_mcp_response_size(ctx, data_to_send, tool_name)

    if retrieve_report_metadata_only:
        await ctx.info(f"MCP Tool '{tool_name}': Returning only Capa report metadata as requested.")
        data_to_send = {"capa_report_metadata": trimmed_report_meta_for_client, 
                        "filtered_rules_summary": {}, "pagination_info": pagination_details}
        return await _check_mcp_response_size(ctx, data_to_send, tool_name)

    # --- Filter and Paginate Rules ---
    all_rules_from_capa_report = capa_full_report_results.get('rules', {}) # This is a dict: rule_id -> rule_details
    if not isinstance(all_rules_from_capa_report, dict):
        pagination_details['total_capabilities_in_original_report'] = 0
        err_msg_rules_format = "Capa 'rules' data in report is malformed (not a dictionary)."
        await ctx.error(f"MCP Tool '{tool_name}': {err_msg_rules_format}")
        data_to_send = {"error_message": err_msg_rules_format, "filtered_rules_summary": {},
                        "pagination_info": pagination_details, "capa_report_metadata": trimmed_report_meta_for_client}
        return await _check_mcp_response_size(ctx, data_to_send, tool_name)
        
    pagination_details['total_capabilities_in_original_report'] = len(all_rules_from_capa_report)
    
    # Apply filters
    list_of_filtered_rule_tuples: List[Tuple[str, Dict]] = [] # (rule_id, rule_details_dict)
    for rule_id_iter, rule_details_iter_original in all_rules_from_capa_report.items():
        if not isinstance(rule_details_iter_original, dict): 
            logger.warning(f"MCP Tool '{tool_name}': Skipping malformed rule entry for ID '{rule_id_iter}' during filtering.")
            continue
        
        rule_meta_iter = rule_details_iter_original.get("meta", {})
        if not isinstance(rule_meta_iter, dict): rule_meta_iter = {} # Ensure it's a dict for safe gets

        passes_all_filters = True
        # Rule Name/ID Substring Filter
        if filter_by_rule_name_substring and \
           filter_by_rule_name_substring.lower() not in str(rule_meta_iter.get("name", rule_id_iter)).lower():
            passes_all_filters = False
        # Namespace Exact Filter
        if passes_all_filters and filter_by_namespace_exact and \
           rule_meta_iter.get("namespace", "").lower() != filter_by_namespace_exact.lower():
            passes_all_filters = False
        # ATT&CK ID/Tactic Substring Filter
        if passes_all_filters and filter_by_attck_id_substring:
            attck_values_iter = rule_meta_iter.get("att&ck", [])
            if not isinstance(attck_values_iter, list): attck_values_iter = [str(attck_values_iter)] 
            # Check if filter string is in any part of the ATT&CK entry (ID, tactic, technique)
            if not any(filter_by_attck_id_substring.lower() in 
                       (" ".join(str(v_attck) for v_attck in entry_attck.values()) if isinstance(entry_attck, dict) else str(entry_attck)).lower() 
                       for entry_attck in attck_values_iter):
                passes_all_filters = False
        # MBC ID/Objective/Behavior Substring Filter
        if passes_all_filters and filter_by_mbc_id_substring:
            mbc_values_iter = rule_meta_iter.get("mbc", [])
            if not isinstance(mbc_values_iter, list): mbc_values_iter = [str(mbc_values_iter)]
            if not any(filter_by_mbc_id_substring.lower() in 
                       (" ".join(str(v_mbc) for v_mbc in entry_mbc.values()) if isinstance(entry_mbc, dict) else str(entry_mbc)).lower()
                       for entry_mbc in mbc_values_iter):
                passes_all_filters = False
        
        if passes_all_filters:
            list_of_filtered_rule_tuples.append((rule_id_iter, rule_details_iter_original))
    
    pagination_details['total_rules_after_filtering'] = len(list_of_filtered_rule_tuples)
    
    # Apply pagination (offset and limit) to the filtered list
    rules_for_current_page_tuples = list_of_filtered_rule_tuples[current_rule_offset : current_rule_offset + limit_rules_on_page]
    pagination_details['rules_on_current_page'] = len(rules_for_current_page_tuples)

    # --- Process rules for the current page into summaries ---
    final_rules_summary_output_dict: Dict[str, Dict] = {}
    for rule_id_on_page, original_rule_details_for_page in rules_for_current_page_tuples:
        rule_summary_entry: Dict[str, Any] = {}
        
        # Copy meta, truncate source if needed
        rule_summary_entry["meta"] = copy.deepcopy(original_rule_details_for_page.get("meta", {}))
        
        source_text_original = original_rule_details_for_page.get("source", "")
        if isinstance(source_text_original, str) and source_text_truncate_length is not None:
            if len(source_text_original) > source_text_truncate_length:
                rule_summary_entry["source"] = source_text_original[:source_text_truncate_length] + "... (truncated)"
            else:
                rule_summary_entry["source"] = source_text_original
        else:
            rule_summary_entry["source"] = source_text_original

        # Summarize matches: count unique addresses
        original_matches_field_for_rule = original_rule_details_for_page.get('matches') 
        match_addr_count = 0
        match_summary_note = None
        if original_matches_field_for_rule is None:
            match_summary_note = "Matches field was null/None in original Capa report data."
        elif isinstance(original_matches_field_for_rule, dict): # Expected format: addr_hex_str -> list_of_feature_matches
            match_addr_count = len(original_matches_field_for_rule)
        elif isinstance(original_matches_field_for_rule, list): # Alternative format seen in some capa versions/outputs
            # Attempt to count unique addresses if matches is a list of [addr_obj, detail_obj] pairs
            unique_addresses_in_list_fmt = set()
            for item_match_list in original_matches_field_for_rule:
                if isinstance(item_match_list, list) and len(item_match_list) > 0 and \
                   isinstance(item_match_list[0], dict) and "value" in item_match_list[0]: # Address object
                    unique_addresses_in_list_fmt.add(item_match_list[0]["value"]) 
            match_addr_count = len(unique_addresses_in_list_fmt)
            if not unique_addresses_in_list_fmt and original_matches_field_for_rule: 
                match_summary_note = "Matches field was a list, but no standard address objects found within it for counting."
            elif not original_matches_field_for_rule: 
                match_summary_note = "Matches field was an empty list in original Capa report data."
        else: 
            match_summary_note = f"Original matches data for rule was not a dictionary or list (was {type(original_matches_field_for_rule).__name__}). Cannot count addresses."
        
        rule_summary_entry["match_address_count"] = match_addr_count
        if match_summary_note: rule_summary_entry["match_summary_note"] = match_summary_note
        
        final_rules_summary_output_dict[rule_id_on_page] = rule_summary_entry

    await ctx.info(f"MCP Tool '{tool_name}': Returning Capa analysis overview. Rules on page: {pagination_details['rules_on_current_page']} of {pagination_details['total_rules_after_filtering']} (total in report: {pagination_details['total_capabilities_in_original_report']}).")
    
    data_to_send_final = {"filtered_rules_summary": final_rules_summary_output_dict, 
                          "pagination_info": pagination_details, 
                          "capa_report_metadata": trimmed_report_meta_for_client}
    
    limit_info_str_capa_overview = ("parameters like 'limit_rules_on_page', 'offset_rules', or by using filters "
                                    "(e.g., 'filter_by_rule_name_substring', 'filter_by_attck_id_substring') "
                                    "to narrow down the number of rules returned.")
    return await _check_mcp_response_size(ctx, data_to_send_final, tool_name, limit_info_str_capa_overview)


@tool_decorator
@mcp_tool_requires_loaded_pe
async def get_capa_rule_match_details(ctx: Context,
                                      rule_id_to_fetch: str,
                                      limit_match_addresses_on_page: int,
                                      offset_match_addresses: Optional[int] = 0,
                                      limit_feature_details_per_address: Optional[int] = None, # Max feature lines per address
                                      # selected_feature_fields_to_show: Optional[List[str]] = None, # Simplified for now
                                      feature_value_text_truncate_length: Optional[int] = None
                                      ) -> Dict[str, Any]:
    """
    Retrieves detailed match information for a single, specified Capa rule from the pre-loaded analysis,
    with pagination for match addresses and content control for feature details.

    Args:
        ctx: The MCP Context object.
        rule_id_to_fetch: (str) Mandatory. The ID/name of the rule to fetch detailed matches for.
        limit_match_addresses_on_page: (int) Mandatory. Max number of match addresses to return for this page. Must be positive.
        offset_match_addresses: (Optional[int]) Starting index for paginating match addresses. Defaults to 0.
        limit_feature_details_per_address: (Optional[int]) Limits the number of individual feature match
                                           details shown for each address. None for no limit on features per address.
        feature_value_text_truncate_length: (Optional[int]) If provided and positive, truncates the 'value'
                                            string within feature objects for display.

    Returns:
        A dictionary containing:
        - "rule_id_requested": (str) The rule ID for which details are provided.
        - "detailed_matches_for_rule_page": (Dict[str, List[Dict]]) A dictionary where keys are address hex strings
                                            and values are lists of feature match detail objects for that address on the current page.
        - "address_pagination_info": (Dict) Details about pagination for match addresses.
        - "error_message": (Optional[str]) If an error occurred (e.g., rule not found).
    Raises:
        RuntimeError: If no Capa analysis data is found.
        ValueError: For invalid parameter values, or if the response size exceeds the server limit.
    """
    tool_name = "get_capa_rule_match_details"
    await ctx.info(f"MCP Tool '{tool_name}': Request. RuleID: '{rule_id_to_fetch}', AddrLimit: {limit_match_addresses_on_page}, AddrOffset: {offset_match_addresses}, "
                   f"FeatDetailLimitPerAddr: {limit_feature_details_per_address}, FeatValTrunc: {feature_value_text_truncate_length}")

    if not rule_id_to_fetch: raise ValueError("Parameter 'rule_id_to_fetch' is mandatory and cannot be empty.")
    if not (isinstance(limit_match_addresses_on_page, int) and limit_match_addresses_on_page > 0):
        raise ValueError("'limit_match_addresses_on_page' must be a positive integer.")
    
    for param_name_check, param_val_check in [
        ('offset_match_addresses', offset_match_addresses),
        ('limit_feature_details_per_address', limit_feature_details_per_address),
        ('feature_value_text_truncate_length', feature_value_text_truncate_length)
    ]:
        if param_val_check is not None and not (isinstance(param_val_check, int) and param_val_check >= 0):
            raise ValueError(f"Parameter '{param_name_check}' must be a non-negative integer if provided.")

    current_addr_offset_val = 0
    if offset_match_addresses is not None: current_addr_offset_val = offset_match_addresses
        
    # --- Retrieve and Validate Capa Data ---
    capa_analysis_block_detail = ANALYZED_PE_DATA.get('capa_rules_analysis', {})
    capa_full_report_results_detail = capa_analysis_block_detail.get('results')
    capa_run_status_detail = capa_analysis_block_detail.get("status", "Unknown")

    # Base pagination info for addresses
    addr_pagination_info = {
        'offset_addresses_applied': current_addr_offset_val, 'limit_addresses_requested': limit_match_addresses_on_page,
        'addresses_on_current_page': 0, 'total_match_addresses_for_this_rule': 0
    }

    if not capa_run_status_detail.startswith("Analysis complete") or not capa_full_report_results_detail:
        err_msg_detail = f"Capa analysis not complete/results missing. Status: {capa_run_status_detail}. Error: {capa_analysis_block_detail.get('error')}"
        await ctx.warning(f"MCP Tool '{tool_name}': {err_msg_detail}")
        data_to_send = {"error_message": err_msg_detail, "rule_id_requested": rule_id_to_fetch,
                        "detailed_matches_for_rule_page": {}, "address_pagination_info": addr_pagination_info}
        return await _check_mcp_response_size(ctx, data_to_send, tool_name)

    all_rules_from_report_detail = capa_full_report_results_detail.get('rules', {})
    if rule_id_to_fetch not in all_rules_from_report_detail:
        err_msg_rule_not_found = f"Rule ID '{rule_id_to_fetch}' not found in Capa analysis results."
        await ctx.warning(f"MCP Tool '{tool_name}': {err_msg_rule_not_found}")
        data_to_send = {"error_message": err_msg_rule_not_found, "rule_id_requested": rule_id_to_fetch,
                        "detailed_matches_for_rule_page": {}, "address_pagination_info": addr_pagination_info}
        return await _check_mcp_response_size(ctx, data_to_send, tool_name)

    # --- Standardize and Paginate Match Addresses ---
    original_rule_details_for_id = all_rules_from_report_detail[rule_id_to_fetch]
    original_matches_field_for_id = original_rule_details_for_id.get('matches') # This is addr_hex -> list_of_feature_matches
    
    standardized_addr_to_feature_list_dict: Dict[str, List[Dict]] = {}
    if isinstance(original_matches_field_for_id, dict):
        for addr_val_key, details_list_val in original_matches_field_for_id.items():
            # Ensure address key is string (hex), and value is a list
            addr_str_key_standard = hex(addr_val_key) if isinstance(addr_val_key, int) else str(addr_val_key)
            if isinstance(details_list_val, list):
                standardized_addr_to_feature_list_dict[addr_str_key_standard] = details_list_val
            else:
                logger.warning(f"MCP Tool '{tool_name}': Malformed match details for address '{addr_str_key_standard}' in rule '{rule_id_to_fetch}'. Expected list, got {type(details_list_val).__name__}.")
                standardized_addr_to_feature_list_dict[addr_str_key_standard] = [{"error_note": "Malformed feature details list in original data."}]

    elif isinstance(original_matches_field_for_id, list): # Handle alternative list format if encountered
        await ctx.info(f"MCP Tool '{tool_name}': Matches for rule '{rule_id_to_fetch}' is a list. Attempting to standardize to address-keyed dictionary.")
        for item_in_match_list_alt in original_matches_field_for_id:
            if isinstance(item_in_match_list_alt, list) and len(item_in_match_list_alt) == 2:
                addr_obj_alt, detail_obj_alt = item_in_match_list_alt[0], item_in_match_list_alt[1]
                if isinstance(addr_obj_alt, dict) and "value" in addr_obj_alt: # Assuming addr_obj has a 'value' field for the address
                    addr_val_alt = addr_obj_alt["value"]
                    addr_str_key_alt = hex(addr_val_alt) if isinstance(addr_val_alt, int) else str(addr_val_alt)
                    
                    if addr_str_key_alt not in standardized_addr_to_feature_list_dict:
                        standardized_addr_to_feature_list_dict[addr_str_key_alt] = []
                    # detail_obj_alt is expected to be the feature match detail dict or list of them
                    if isinstance(detail_obj_alt, dict): standardized_addr_to_feature_list_dict[addr_str_key_alt].append(detail_obj_alt)
                    elif isinstance(detail_obj_alt, list): standardized_addr_to_feature_list_dict[addr_str_key_alt].extend(detail_obj_alt)
                else:
                    logger.warning(f"MCP Tool '{tool_name}': Skipped item in list-formatted matches for rule '{rule_id_to_fetch}': address object malformed. Item snippet: {str(item_in_match_list_alt)[:150]}")
            else:
                logger.warning(f"MCP Tool '{tool_name}': Skipped item in list-formatted matches for rule '{rule_id_to_fetch}': item not a pair or malformed. Item snippet: {str(item_in_match_list_alt)[:150]}")
    
    elif original_matches_field_for_id is None:
        await ctx.info(f"MCP Tool '{tool_name}': No 'matches' data found for rule '{rule_id_to_fetch}'.")
    else:
        await ctx.warning(f"MCP Tool '{tool_name}': 'matches' data for rule '{rule_id_to_fetch}' is of unexpected type '{type(original_matches_field_for_id).__name__}'. Treating as no matches.")

    # Get sorted list of (address_str, feature_list) items for pagination
    all_match_addresses_sorted_items = sorted(standardized_addr_to_feature_list_dict.items())
    addr_pagination_info['total_match_addresses_for_this_rule'] = len(all_match_addresses_sorted_items)
    
    # Paginate the address entries
    paginated_address_entries_tuples = all_match_addresses_sorted_items[current_addr_offset_val : current_addr_offset_val + limit_match_addresses_on_page]
    addr_pagination_info['addresses_on_current_page'] = len(paginated_address_entries_tuples)

    # --- Process Feature Details for each address on the current page ---
    final_detailed_matches_for_page: Dict[str, List[Dict]] = {} 
    for addr_key_on_page_str, original_feature_list_for_addr_on_page in paginated_address_entries_tuples:
        processed_feature_list_for_this_addr: List[Dict] = []
        
        # Make a deepcopy to avoid modifying the global ANALYZED_PE_DATA
        feature_list_to_process_copy = copy.deepcopy(original_feature_list_for_addr_on_page) 
        
        if not isinstance(feature_list_to_process_copy, list): 
            # This case should be rare if standardization worked, but handle defensively
            processed_feature_list_for_this_addr.append({"error_note": "Feature details structure error after standardization for this address."})
            final_detailed_matches_for_page[addr_key_on_page_str] = processed_feature_list_for_this_addr
            continue

        num_feature_details_to_take = len(feature_list_to_process_copy)
        if limit_feature_details_per_address is not None:
            if limit_feature_details_per_address == 0: # If limit is 0, return empty list for this address
                final_detailed_matches_for_page[addr_key_on_page_str] = [] 
                continue 
            num_feature_details_to_take = min(len(feature_list_to_process_copy), limit_feature_details_per_address)

        for i in range(num_feature_details_to_take):
            feature_detail_item_processed = feature_list_to_process_copy[i] 

            if isinstance(feature_detail_item_processed, dict) and \
               'feature' in feature_detail_item_processed and \
               isinstance(feature_detail_item_processed['feature'], dict):
                
                feature_object_to_modify = feature_detail_item_processed['feature'] 
                
                # Truncate 'value' string in feature object if requested
                if 'value' in feature_object_to_modify and \
                   isinstance(feature_object_to_modify['value'], str) and \
                   feature_value_text_truncate_length is not None and feature_value_text_truncate_length >= 0: # Check >=0
                    original_feature_val_str = feature_object_to_modify['value']
                    if len(original_feature_val_str) > feature_value_text_truncate_length:
                        feature_object_to_modify['value'] = original_feature_val_str[:feature_value_text_truncate_length] + "... (truncated)"
                
                # No specific field selection for 'feature' object for now, returning all its fields.
                # If selected_feature_fields_to_show was implemented, it would filter feature_object_to_modify here.
            
            processed_feature_list_for_this_addr.append(feature_detail_item_processed)
        
        final_detailed_matches_for_page[addr_key_on_page_str] = processed_feature_list_for_this_addr

    await ctx.info(f"MCP Tool '{tool_name}': Returning match details for rule '{rule_id_to_fetch}'. "
                   f"Addresses on page: {addr_pagination_info['addresses_on_current_page']} of {addr_pagination_info['total_match_addresses_for_this_rule']}.")
    
    data_to_send_final_details = {"rule_id_requested": rule_id_to_fetch, 
                                  "detailed_matches_for_rule_page": final_detailed_matches_for_page, 
                                  "address_pagination_info": addr_pagination_info}
    
    limit_info_str_capa_details = ("parameters like 'limit_match_addresses_on_page', 'offset_match_addresses', "
                                   "or 'limit_feature_details_per_address' to manage the amount of data returned.")
    return await _check_mcp_response_size(ctx, data_to_send_final_details, tool_name, limit_info_str_capa_details)


@tool_decorator
@mcp_tool_requires_loaded_pe
async def extract_strings_from_loaded_binary(ctx: Context, # Renamed for clarity
                                             limit_strings_returned: int, 
                                             min_string_length: int = 5
                                             ) -> List[Dict[str, Any]]: # List of {"offset": hex_str, "string": str_val}
    """
    Extracts printable ASCII strings from the pre-loaded PE file's binary data.

    Args:
        ctx: The MCP Context object.
        limit_strings_returned: (int) Mandatory. Max number of strings to return. Must be positive.
        min_string_length: (int) Min length for a char sequence to be a string. Defaults to 5. Must be positive.

    Returns:
        A list of dictionaries, each with "offset" (hex) and "string". Empty if no PE or no strings.
    Raises:
        ValueError: If parameters are invalid, or if response size limit hit.
    """
    tool_name = "extract_strings_from_loaded_binary"
    await ctx.info(f"MCP Tool '{tool_name}': Request. MinLen: {min_string_length}, Limit: {limit_strings_returned}")

    if not (isinstance(limit_strings_returned, int) and limit_strings_returned > 0):
        raise ValueError("Parameter 'limit_strings_returned' must be a positive integer.")
    if not (isinstance(min_string_length, int) and min_string_length > 0): # Min length should be at least 1
        raise ValueError("Parameter 'min_string_length' must be a positive integer.")

    # PE_OBJECT_FOR_MCP and its __data__ are guaranteed by decorator
    try:
        file_data_bytes = PE_OBJECT_FOR_MCP.__data__
        # Use the synchronous helper; to_thread if it becomes very slow, but string extraction is often fast enough.
        # For very large files, this could be a concern.
        found_strings_tuples = await asyncio.to_thread(_extract_strings_from_data, file_data_bytes, min_string_length)
        
        results_list_of_dicts = [{"offset": hex(offset_val), "string": s_val} for offset_val, s_val in found_strings_tuples]
        
        data_to_send_strings = results_list_of_dicts[:limit_strings_returned] # Apply limit
        limit_info_str_strings = "the 'limit_strings_returned' parameter or by increasing 'min_string_length'"
        return await _check_mcp_response_size(ctx, data_to_send_strings, tool_name, limit_info_str_strings)

    except Exception as e_str_extract_mcp: # Catch any error from _extract_strings_from_data or processing
        err_msg_str = f"Error during string extraction for loaded binary: {e_str_extract_mcp}"
        await ctx.error(err_msg_str)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_str}", exc_info=True)
        # Return an error structure that _check_mcp_response_size can handle (it will be small)
        return await _check_mcp_response_size(ctx, {"error": err_msg_str, "strings": []}, tool_name)


@tool_decorator
@mcp_tool_requires_loaded_pe
async def search_for_specific_strings_in_loaded_binary(ctx: Context, # Renamed
                                                       list_of_search_terms: List[str], 
                                                       limit_occurrences_per_term: Optional[int] = 100
                                                       ) -> Dict[str, List[str]]: # Term -> List of hex offsets
    """
    Searches for occurrences of specific ASCII strings within the pre-loaded PE file's binary data.
    Search is case-sensitive. 'limit_occurrences_per_term' controls occurrences per search term.

    Args:
        ctx: The MCP Context object.
        list_of_search_terms: (List[str]) A list of ASCII strings to search for.
        limit_occurrences_per_term: (Optional[int]) Max occurrences to report per term. Default 100.
                                     If None, 0, or negative, a default internal limit (e.g., 100) applies.

    Returns:
        A dictionary: keys are search terms, values are lists of hex offsets of occurrences.
    Raises:
        ValueError: If `list_of_search_terms` is empty/not a list, or if response size limit hit.
    """
    tool_name = "search_for_specific_strings_in_loaded_binary"
    await ctx.info(f"MCP Tool '{tool_name}': Request. Terms: {list_of_search_terms}, LimitPerTerm: {limit_occurrences_per_term}")

    if not list_of_search_terms or not isinstance(list_of_search_terms, list) or \
       not all(isinstance(term, str) for term in list_of_search_terms) : 
        raise ValueError("Parameter 'list_of_search_terms' must be a non-empty list of strings.")

    effective_limit_per_term_val = 100 # Default
    if limit_occurrences_per_term is not None and isinstance(limit_occurrences_per_term, int) and limit_occurrences_per_term > 0:
        effective_limit_per_term_val = limit_occurrences_per_term
    elif limit_occurrences_per_term is not None: # Invalid value provided
        await ctx.warning(f"MCP Tool '{tool_name}': Invalid 'limit_occurrences_per_term' value '{limit_occurrences_per_term}'. Using default of {effective_limit_per_term_val}.")

    try:
        file_data_bytes_search = PE_OBJECT_FOR_MCP.__data__
        # Use synchronous helper; to_thread if performance becomes an issue for huge files / many terms.
        found_offsets_by_term_dict_int = await asyncio.to_thread(_search_specific_strings_in_data, file_data_bytes_search, list_of_search_terms)

        limited_results_hex_offsets: Dict[str, List[str]] = {}
        for term_key, offsets_list_as_int in found_offsets_by_term_dict_int.items():
            limited_results_hex_offsets[term_key] = [hex(offset_val_int) for offset_val_int in offsets_list_as_int[:effective_limit_per_term_val]]
        
        limit_info_str_search = ("the 'limit_occurrences_per_term' parameter or by providing fewer/more specific 'list_of_search_terms'")
        return await _check_mcp_response_size(ctx, limited_results_hex_offsets, tool_name, limit_info_str_search)

    except Exception as e_search_spec_mcp:
        err_msg_search = f"Error during specific string search for loaded binary: {e_search_spec_mcp}"
        await ctx.error(err_msg_search)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_search}", exc_info=True)
        return await _check_mcp_response_size(ctx, {"error": err_msg_search, "search_results": {}}, tool_name)


@tool_decorator
@mcp_tool_requires_loaded_pe
async def get_hex_dump_from_loaded_binary(ctx: Context, # Renamed
                                          start_file_offset: int, 
                                          length_of_dump_bytes: int, 
                                          bytes_to_show_per_line: Optional[int] = 16, 
                                          limit_output_lines: Optional[int] = 256
                                          ) -> List[str]: # List of formatted hex dump lines
    """
    Retrieves a hex dump of a specified region from the pre-loaded PE file.
    'limit_output_lines' controls the number of lines in the output.

    Args:
        ctx: The MCP Context object.
        start_file_offset: (int) The starting offset (0-based) in the file.
        length_of_dump_bytes: (int) Number of bytes to include. Must be positive.
        bytes_to_show_per_line: (Optional[int]) Bytes per line. Default 16. Must be positive.
        limit_output_lines: (Optional[int]) Max lines to return. Default 256. Must be positive.

    Returns:
        A list of strings, each a formatted line of the hex dump. Can include error messages.
    Raises:
        ValueError: If inputs are invalid, or if response size limit hit.
    """
    tool_name = "get_hex_dump_from_loaded_binary"
    await ctx.info(f"MCP Tool '{tool_name}': Request. Offset {hex(start_file_offset)}, Length {length_of_dump_bytes}, Bytes/Line {bytes_to_show_per_line}, LimitLines {limit_output_lines}")

    if not (isinstance(start_file_offset, int) and start_file_offset >= 0):
        raise ValueError("'start_file_offset' must be a non-negative integer.")
    if not (isinstance(length_of_dump_bytes, int) and length_of_dump_bytes > 0):
        raise ValueError("'length_of_dump_bytes' must be a positive integer.")

    bytes_per_line_eff = 16
    if bytes_to_show_per_line is not None:
        if not (isinstance(bytes_to_show_per_line, int) and bytes_to_show_per_line > 0):
            raise ValueError("'bytes_to_show_per_line' must be a positive integer if provided.")
        bytes_per_line_eff = bytes_to_show_per_line

    limit_lines_eff = 256
    if limit_output_lines is not None:
        if not (isinstance(limit_output_lines, int) and limit_output_lines > 0):
            raise ValueError("'limit_output_lines' must be a positive integer if provided.")
        limit_lines_eff = limit_output_lines
    
    try:
        file_data_for_hex_dump = PE_OBJECT_FOR_MCP.__data__
        file_total_size = len(file_data_for_hex_dump)

        if start_file_offset >= file_total_size:
            msg_offset_err = "Error: Start offset for hex dump is beyond the file size."
            await ctx.warning(f"MCP Tool '{tool_name}': {msg_offset_err}")
            # Return as list of strings for consistency, size check will pass
            return await _check_mcp_response_size(ctx, [msg_offset_err], tool_name) 
            
        actual_length_to_dump = min(length_of_dump_bytes, file_total_size - start_file_offset)
        if actual_length_to_dump <= 0:
            msg_len_err = "Error: Calculated length for hex dump is zero or negative (start_offset might be at or past EOF for requested length)."
            await ctx.warning(f"MCP Tool '{tool_name}': {msg_len_err}")
            return await _check_mcp_response_size(ctx, [msg_len_err], tool_name)

        data_chunk_for_formatting = file_data_for_hex_dump[start_file_offset : start_file_offset + actual_length_to_dump]
        # _format_hex_dump_lines is synchronous and usually fast for reasonable chunks.
        # If length_of_dump_bytes can be huge, consider to_thread for formatting too.
        hex_dump_lines_formatted = await asyncio.to_thread(_format_hex_dump_lines, data_chunk_for_formatting, start_file_offset, bytes_per_line_eff)
        
        data_to_send_hexdump = hex_dump_lines_formatted[:limit_lines_eff] # Apply line limit
        limit_info_str_hexdump = "parameters like 'length_of_dump_bytes' or 'limit_output_lines'"
        return await _check_mcp_response_size(ctx, data_to_send_hexdump, tool_name, limit_info_str_hexdump)

    except Exception as e_hexdump_mcp:
        err_msg_hexdump = f"Error during hex dump generation: {e_hexdump_mcp}"
        await ctx.error(err_msg_hexdump)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_hexdump}", exc_info=True)
        return await _check_mcp_response_size(ctx, [f"Error: {err_msg_hexdump}"], tool_name)


@tool_decorator
async def deobfuscate_base64_string_from_hex(ctx: Context, input_hex_encoded_base64_string: str) -> Optional[str]: # Renamed arg
    """
    Deobfuscates a hex-encoded string that is presumed to represent Base64 encoded data.
    The input 'input_hex_encoded_base64_string' should be the hexadecimal representation of a Base64 string.
    Example: If original data is "test", its Base64 is "dGVzdA==", then the hex of "dGVzdA==" is "6447567a64413d3d".
             This function expects "6447567a64413d3d" as input.

    Args:
        ctx: The MCP Context object.
        input_hex_encoded_base64_string: (str) The hex-encoded string of the Base64 data.

    Returns:
        (Optional[str]) The deobfuscated string (UTF-8 decoded, errors ignored/replaced).
                        Returns None if deobfuscation fails (e.g., invalid hex, not valid Base64).
    Raises:
        ValueError: If response size exceeds server limit (though decoded string is usually small unless hex input is huge).
    """
    tool_name = "deobfuscate_base64_string_from_hex"
    # Log only a snippet of potentially long hex string
    log_snippet_hex = input_hex_encoded_base64_string[:80] + ("..." if len(input_hex_encoded_base64_string) > 80 else "")
    await ctx.info(f"MCP Tool '{tool_name}': Attempting to deobfuscate Base64 from hex: {log_snippet_hex}")
    
    decoded_string_result: Optional[str] = None
    try:
        # Convert hex string to bytes (this is the actual Base64 encoded data)
        base64_encoded_as_bytes = bytes.fromhex(input_hex_encoded_base64_string)
        # Decode the Base64 bytes to get the original payload bytes
        original_payload_as_bytes = codecs.decode(base64_encoded_as_bytes, 'base64') # pyright: ignore [reportUnknownMemberType]
        # Decode the original payload bytes into a string (assume UTF-8, replace errors)
        decoded_string_result = original_payload_as_bytes.decode('utf-8', 'replace') # Use 'replace' for robustness
        await ctx.info(f"MCP Tool '{tool_name}': Base64 deobfuscation successful. Decoded string length: {len(decoded_string_result)}")
        
    except ValueError as e_val_b64: # Handles bytes.fromhex error if input_hex_... is not valid hex
        err_msg_b64_val = f"Invalid hex string provided for Base64 deobfuscation: {str(e_val_b64)}"
        await ctx.error(err_msg_b64_val)
        logger.warning(f"MCP Tool '{tool_name}': {err_msg_b64_val} (Input snippet: {log_snippet_hex})")
        # decoded_string_result remains None
    except binascii.Error as e_b64_decode: # codecs.decode for 'base64' can raise binascii.Error for invalid Base64
        err_msg_b64_data = f"Invalid Base64 data after hex decoding: {str(e_b64_decode)}"
        await ctx.error(err_msg_b64_data)
        logger.warning(f"MCP Tool '{tool_name}': {err_msg_b64_data} (Input snippet: {log_snippet_hex})")
        # decoded_string_result remains None
    except Exception as e_gen_b64: # Catch other unexpected errors
        err_msg_b64_gen = f"Base64 deobfuscation unexpected error: {str(e_gen_b64)}"
        await ctx.error(err_msg_b64_gen)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_b64_gen} (Input snippet: {log_snippet_hex})", exc_info=True)
        # decoded_string_result remains None

    limit_info_str_b64 = ("a shorter 'input_hex_encoded_base64_string' if the resulting decoded string is excessively large. "
                          "This tool has no direct data limiting parameters for the output string itself.")
    return await _check_mcp_response_size(ctx, decoded_string_result, tool_name, limit_info_str_b64)


@tool_decorator
async def deobfuscate_data_with_single_byte_xor(ctx: Context, # Renamed
                                                input_hex_encoded_data: str, 
                                                xor_key_byte_int: int
                                                ) -> Dict[str, Optional[str]]:
    """
    Deobfuscates a hex-encoded data string using a single-byte XOR key.

    Args:
        ctx: The MCP Context object.
        input_hex_encoded_data: (str) The hex-encoded data string to be XORed.
        xor_key_byte_int: (int) The single byte (0-255) to use as the XOR key.

    Returns:
        A dictionary containing:
        - "deobfuscated_data_hex": (str) Hex representation of the XORed data.
        - "deobfuscated_data_printable_string": (Optional[str]) A printable representation of XORed data
          (UTF-8 or Latin-1 decoded if possible, else dot-replaced non-printables). None on error.
        - "error_message": (Optional[str]) If an error occurred during processing.
    Raises:
        ValueError: If `xor_key_byte_int` is invalid, `input_hex_encoded_data` is not valid hex,
                    or if response size exceeds server limit.
    """
    tool_name = "deobfuscate_data_with_single_byte_xor"
    log_snippet_hex_xor = input_hex_encoded_data[:80] + ("..." if len(input_hex_encoded_data) > 80 else "")
    await ctx.info(f"MCP Tool '{tool_name}': Attempting XOR deobfuscation. DataHex (snippet): '{log_snippet_hex_xor}', Key: {xor_key_byte_int:#04x} ({xor_key_byte_int})")

    if not (0 <= xor_key_byte_int <= 255):
        err_msg_key = f"XOR key must be an integer between 0 and 255. Received: {xor_key_byte_int}"
        await ctx.error(err_msg_key)
        logger.warning(f"MCP Tool '{tool_name}': Invalid XOR key {xor_key_byte_int} requested.")
        # Raise ValueError to make MCP return error to client, rather than returning a dict that _check_mcp_response_size would process.
        raise ValueError(err_msg_key) 

    result_payload: Dict[str, Optional[str]] = {
        "deobfuscated_data_hex": None,
        "deobfuscated_data_printable_string": None,
        "error_message": None
    }

    try:
        data_as_bytes = bytes.fromhex(input_hex_encoded_data)
        deobfuscated_result_bytes = bytes([b ^ xor_key_byte_int for b in data_as_bytes])
        
        result_payload["deobfuscated_data_hex"] = deobfuscated_result_bytes.hex()

        # Attempt to create a printable string representation
        printable_str_repr = None
        try:
            try: printable_str_repr = deobfuscated_result_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try: printable_str_repr = deobfuscated_result_bytes.decode('latin-1') # Try common alternative
                except UnicodeDecodeError: # Fallback to dot-replacement for non-printables
                    printable_str_repr = "".join(chr(b_val) if 32 <= b_val <= 126 or b_val in [9,10,13] else '.' for b_val in deobfuscated_result_bytes)
        except Exception as e_decode_print: # Should be rare if fallbacks are robust
            logger.warning(f"MCP Tool '{tool_name}': Error creating printable string for XOR result (key {xor_key_byte_int}): {e_decode_print}")
            printable_str_repr = "[Error creating printable string representation]"
        result_payload["deobfuscated_data_printable_string"] = printable_str_repr
        
        await ctx.info(f"MCP Tool '{tool_name}': XOR deobfuscation successful.")
        
    except ValueError as e_val_xor: # Handles bytes.fromhex error
        err_msg_hex_xor = f"Invalid hex string provided for XOR data: {str(e_val_xor)}"
        result_payload["error_message"] = err_msg_hex_xor
        await ctx.error(err_msg_hex_xor)
        logger.warning(f"MCP Tool '{tool_name}': Invalid hex for XOR data (snippet: {log_snippet_hex_xor}) - {str(e_val_xor)}")
        # Do not re-raise here, let _check_mcp_response_size handle the error payload
    except Exception as e_gen_xor:
        err_msg_gen_xor = f"XOR deobfuscation unexpected error: {str(e_gen_xor)}"
        result_payload["error_message"] = err_msg_gen_xor
        await ctx.error(err_msg_gen_xor)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_gen_xor} (Data snippet: {log_snippet_hex_xor}, Key: {xor_key_byte_int})", exc_info=True)
        # Do not re-raise here

    limit_info_str_xor = ("a shorter 'input_hex_encoded_data' if the deobfuscated content is excessively large. "
                          "This tool has no direct data limiting parameters for the output string itself.")
    return await _check_mcp_response_size(ctx, result_payload, tool_name, limit_info_str_xor)

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
    
    if not text_input: return False 

    ratio = printable_char_in_string_count / len(text_input)
    return ratio >= threshold

@tool_decorator
async def check_string_if_mostly_printable_ascii(ctx: Context, # Renamed
                                                 string_to_check: str, 
                                                 min_printable_ratio_threshold: float = 0.8
                                                 ) -> bool:
    """
    Checks if the given 'string_to_check' consists mostly of printable ASCII characters.
    Printable includes standard ASCII (space to '~') and common whitespace (newline, tab, carriage return).

    Args:
        ctx: The MCP Context object.
        string_to_check: (str) The string to evaluate.
        min_printable_ratio_threshold: (float) Min ratio (0.0-1.0) of printable chars to total chars
                                       for the string to be "mostly printable". Default 0.8 (80%).

    Returns:
        (bool) True if printable ratio meets/exceeds threshold, False otherwise. False for empty input.
    Raises:
        ValueError: If `min_printable_ratio_threshold` is not between 0.0 and 1.0.
    """
    tool_name = "check_string_if_mostly_printable_ascii"
    # Log only length and a snippet for potentially very long strings
    log_snippet_str_check = string_to_check[:80] + ("..." if len(string_to_check) > 80 else "")
    await ctx.info(f"MCP Tool '{tool_name}': Request. Threshold: {min_printable_ratio_threshold}, String (snippet): '{log_snippet_str_check}', Length: {len(string_to_check)}")

    if not (0.0 <= min_printable_ratio_threshold <= 1.0):
        err_msg_thresh = f"Threshold for printable check must be between 0.0 and 1.0. Received: {min_printable_ratio_threshold}"
        await ctx.error(err_msg_thresh)
        logger.warning(f"MCP Tool '{tool_name}': Invalid threshold {min_printable_ratio_threshold}.")
        raise ValueError(err_msg_thresh)

    if not string_to_check: # Handle empty string explicitly
        await ctx.info(f"MCP Tool '{tool_name}': Input string is empty, returning False for printable check.")
        return False # An empty string is not "mostly printable" by this definition

    # Use the synchronous helper. This operation should be very fast.
    is_printable_result = _is_mostly_printable_ascii_sync(string_to_check, min_printable_ratio_threshold)
    
    # Calculate ratio again for logging if needed, or trust the sync helper's logic
    # printable_chars_count = sum(1 for char_val in string_to_check if (' ' <= char_val <= '~') or char_val in '\n\r\t')
    # actual_ratio = printable_chars_count / len(string_to_check) if len(string_to_check) > 0 else 0
    # await ctx.info(f"MCP Tool '{tool_name}': Printable character ratio: {actual_ratio:.3f}. Result: {is_printable_result}")
    await ctx.info(f"MCP Tool '{tool_name}': Printable check result: {is_printable_result}")
    
    # Boolean result is very small, no need for _check_mcp_response_size
    return is_printable_result
   
@tool_decorator
@mcp_tool_requires_loaded_pe # Needs PE_OBJECT_FOR_MCP.__data__
async def find_and_decode_common_encoded_substrings( # Renamed
    ctx: Context,
    limit_decoded_results: int,
    min_len_base64_candidate: int = 20,
    min_len_base32_candidate: int = 24, 
    min_len_hex_candidate: int = 8,  
    min_len_url_candidate: int = 10, # Increased default slightly for URL
    min_len_decoded_printable_string: int = 4,
    min_printable_char_ratio: float = 0.8,
    regex_patterns_for_decoded_strings: Optional[List[str]] = None # List of regex strings
) -> List[Dict[str, Any]]:
    """
    Searches the pre-loaded binary for potential Base64, Base32, Hex, or URL encoded
    substrings. Attempts to decode them, filters by printability and length, 
    and optionally filters by custom regex patterns applied to the decoded strings.

    Args:
        ctx: The MCP Context object.
        limit_decoded_results: (int) Max number of decoded results to return. Must be positive.
        min_len_base64_candidate: (int) Min length of a potential Base64 sequence. Default 20.
        min_len_base32_candidate: (int) Min length of a potential Base32 sequence. Default 24.
        min_len_hex_candidate: (int) Min length of a potential Hex sequence (e.g., "AABBCCDD"). Default 8.
        min_len_url_candidate: (int) Min length of a potential URL-encoded sequence (e.g., "%20%41"). Default 10.
        min_len_decoded_printable_string: (int) Min length of a successfully decoded and printable string. Default 4.
        min_printable_char_ratio: (float) Ratio (0.0-1.0) of printable chars for decoded data. Default 0.8.
        regex_patterns_for_decoded_strings: (Optional[List[str]]) List of regex patterns (as strings)
                                          to search for within successfully decoded strings. If provided, a decoded string
                                          must match at least one pattern. Case-sensitive by default. Default None.

    Returns:
        A list of dictionaries, each representing a successfully decoded and filtered string.
        Each dict contains: "original_match_offset_hex", "original_match_snippet_hex",
        "encoded_substring_repr_snippet", "detected_encoding_type", "decoded_string_content", "decoded_string_length".
    Raises:
        RuntimeError: If no PE file is loaded or an unexpected error occurs during processing.
        ValueError: For invalid parameter values (including invalid regex patterns), or if response size exceeds server limit.
    """
    tool_name = "find_and_decode_common_encoded_substrings"
    await ctx.info(f"MCP Tool '{tool_name}': Request. LimitResults: {limit_decoded_results}, "
                   f"MinLens(B64/B32/Hex/URL): {min_len_base64_candidate}/{min_len_base32_candidate}/{min_len_hex_candidate}/{min_len_url_candidate}, "
                   f"MinDecodedLen: {min_len_decoded_printable_string}, PrintableRatio: {min_printable_char_ratio}, "
                   f"DecodedRegexPatterns: {regex_patterns_for_decoded_strings is not None}")

    # --- Parameter Validation ---
    if not (isinstance(limit_decoded_results, int) and limit_decoded_results > 0):
        raise ValueError("Parameter 'limit_decoded_results' must be a positive integer.")
    for p_name, p_val, p_min_val in [
        ("min_len_base64_candidate", min_len_base64_candidate, 4), ("min_len_base32_candidate", min_len_base32_candidate, 8),
        ("min_len_hex_candidate", min_len_hex_candidate, 2), ("min_len_url_candidate", min_len_url_candidate, 3), 
        ("min_len_decoded_printable_string", min_len_decoded_printable_string, 1)
    ]:
        if not (isinstance(p_val, int) and p_val >= p_min_val):
            raise ValueError(f"Parameter '{p_name}' must be an integer >= {p_min_val}.")
    if not (0.0 <= min_printable_char_ratio <= 1.0):
        raise ValueError("Parameter 'min_printable_char_ratio' must be between 0.0 and 1.0.")

    compiled_regex_list_for_decoded: List[re.Pattern] = []
    if regex_patterns_for_decoded_strings:
        if not isinstance(regex_patterns_for_decoded_strings, list) or \
           not all(isinstance(p_str, str) for p_str in regex_patterns_for_decoded_strings):
            raise ValueError("Parameter 'regex_patterns_for_decoded_strings' must be a list of strings if provided.")
        try:
            for pattern_str_to_compile in regex_patterns_for_decoded_strings:
                compiled_regex_list_for_decoded.append(re.compile(pattern_str_to_compile)) # Default flags (case-sensitive)
            await ctx.info(f"MCP Tool '{tool_name}': Successfully compiled {len(compiled_regex_list_for_decoded)} regex patterns for decoded strings.")
        except re.error as e_re_compile_decoded:
            err_msg_re_decoded = f"Invalid regex pattern in 'regex_patterns_for_decoded_strings': {e_re_compile_decoded}"
            await ctx.error(err_msg_re_decoded)
            raise ValueError(err_msg_re_decoded) from e_re_compile_decoded

    # PE_OBJECT_FOR_MCP.__data__ is guaranteed by decorator
    full_file_data_bytes = PE_OBJECT_FOR_MCP.__data__
    found_and_decoded_results_list: List[Dict[str, Any]] = []

    # --- Define Regex for Candidate Encoded Strings ---
    # Base64: Chars A-Z, a-z, 0-9, +, /. Padding =. Min length of 4.
    # Stricter regex: (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?
    # Simpler for finditer: sequence of B64 chars, then check padding and length in code.
    base64_candidate_chars_pattern = re.compile(rb"[A-Za-z0-9+/=]+") # Includes padding char for initial match
    
    # Base32: Chars A-Z, 2-7. Padding =. Min length of 8.
    base32_candidate_chars_pattern = re.compile(rb"[A-Z2-7=]+")
    
    # Hex: Chars 0-9, a-f, A-F. Must be even length.
    hex_candidate_pattern = re.compile(rb"(?:[0-9a-fA-F]{2})+") # Matches sequences of hex pairs

    # URL Encoding: % followed by two hex digits.
    # A simple pattern to find potential URL encoded segments. More complex URL parsing is harder with regex alone.
    # This looks for sequences containing at least one %HH.
    url_percent_char_set = rb"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]" # Unreserved + some reserved that might appear unencoded
    url_encoded_segment_pattern = re.compile(rb"(?:%[0-9a-fA-F]{2}|" + url_percent_char_set + rb")+")


    # List of (encoding_type, regex_pattern, min_candidate_len, decode_function)
    # Decode functions should take bytes and return bytes, or raise error.
    decoding_pipeline_config = [
        ("Base64", base64_candidate_chars_pattern, min_len_base64_candidate, lambda b: base64.b64decode(b, validate=True)), # validate=True for stricter B64
        ("Base32", base32_candidate_chars_pattern, min_len_base32_candidate, base64.b32decode), # b32decode handles padding
        ("Hex", hex_candidate_pattern, min_len_hex_candidate, bytes.fromhex),
        ("URL", url_encoded_segment_pattern, min_len_url_candidate, urllib.parse.unquote_to_bytes) 
    ]

    # To avoid re-processing overlapping matches from different regexes (e.g. a hex string is also valid B64 chars)
    processed_offsets_ranges: Set[Tuple[int, int]] = set() 

    try:
        for encoding_type_name, candidate_regex, min_cand_len_val, decode_function_sync in decoding_pipeline_config:
            if len(found_and_decoded_results_list) >= limit_decoded_results: break # Stop if limit reached
            
            await ctx.info(f"MCP Tool '{tool_name}': Scanning for {encoding_type_name} patterns...")
            for match_obj in candidate_regex.finditer(full_file_data_bytes):
                if len(found_and_decoded_results_list) >= limit_decoded_results: break
                
                start_offset_match, end_offset_match = match_obj.start(), match_obj.end()
                
                # Check if this exact range has been processed by a previous, possibly more specific, decoder
                # This is a simple check; more sophisticated overlap detection could be added if needed.
                is_already_processed = False
                for proc_start, proc_end in processed_offsets_ranges:
                    if proc_start <= start_offset_match and proc_end >= end_offset_match: # Current match is within/equal to a processed one
                        is_already_processed = True; break
                if is_already_processed: continue

                encoded_candidate_bytes = match_obj.group(0)

                if len(encoded_candidate_bytes) < min_cand_len_val: continue
                
                # Specific checks for some encodings before attempting decode
                if encoding_type_name == "Hex" and len(encoded_candidate_bytes) % 2 != 0: continue # Hex must be even length
                if encoding_type_name == "URL" and b'%' not in encoded_candidate_bytes: continue # URL encoding must have at least one %

                try:
                    # Perform synchronous decode in a thread to avoid blocking
                    decoded_payload_bytes = await asyncio.to_thread(decode_function_sync, encoded_candidate_bytes)
                    
                    if not decoded_payload_bytes: continue # Empty result after decode

                    # Try to decode to string (UTF-8, then fallback with replacement)
                    try: decoded_payload_text = decoded_payload_bytes.decode('utf-8')
                    except UnicodeDecodeError: decoded_payload_text = decoded_payload_bytes.decode('latin-1', 'replace') # Fallback
                    
                    # --- Apply Filters to Decoded Text ---
                    passes_decoded_len_check = len(decoded_payload_text) >= min_len_decoded_printable_string
                    passes_decoded_printable_check = _is_mostly_printable_ascii_sync(decoded_payload_text, min_printable_char_ratio)

                    if passes_decoded_len_check and passes_decoded_printable_check:
                        # Apply custom regex filter if provided
                        matches_any_custom_regex = False
                        if not compiled_regex_list_for_decoded: # No regexes to filter by
                            matches_any_custom_regex = True
                        else:
                            for compiled_regex_pattern_custom in compiled_regex_list_for_decoded:
                                if compiled_regex_pattern_custom.search(decoded_payload_text):
                                    matches_any_custom_regex = True; break
                        
                        if matches_any_custom_regex: 
                            # Create snippet of original data around the match for context
                            snippet_context_start = max(0, start_offset_match - 16)
                            snippet_context_end = min(len(full_file_data_bytes), end_offset_match + 16)
                            
                            found_and_decoded_results_list.append({
                                "original_match_offset_hex": hex(start_offset_match),
                                "original_match_length_bytes": len(encoded_candidate_bytes),
                                "original_match_context_snippet_hex": full_file_data_bytes[snippet_context_start:snippet_context_end].hex(),
                                "encoded_substring_repr_snippet": encoded_candidate_bytes.decode('ascii', 'replace')[:200], # Snippet of matched encoded form
                                "detected_encoding_type": encoding_type_name,
                                "decoded_string_content": decoded_payload_text,
                                "decoded_string_length": len(decoded_payload_text)
                            })
                            processed_offsets_ranges.add((start_offset_match, end_offset_match)) # Mark this range as processed

                            if len(found_and_decoded_results_list) >= limit_decoded_results: break # Check limit again
                
                except (binascii.Error, ValueError, TypeError, UnicodeDecodeError) as e_decode_inner: 
                    # These errors are expected if a candidate string is not actually the encoding type
                    # For debugging, can log: logger.debug(f"Decode attempt failed for {encoding_type_name} candidate at {hex(start_offset_match)}: {e_decode_inner}")
                    pass 
                except Exception as e_generic_decode_inner: # Catch any other unexpected error during decode_function call
                    logger.warning(f"MCP Tool '{tool_name}': Unexpected error during {encoding_type_name} decode for candidate at {hex(start_offset_match)}: {e_generic_decode_inner}")
                    pass # Continue to next match or encoding type

        await ctx.info(f"MCP Tool '{tool_name}': Found {len(found_and_decoded_results_list)} decoded strings matching all criteria.")
        
        limit_info_str_find_decode = ("the 'limit_decoded_results' parameter, or by adjusting minimum candidate lengths "
                                      "(e.g., 'min_len_base64_candidate'), 'min_len_decoded_printable_string', "
                                      "'min_printable_char_ratio', or by providing 'regex_patterns_for_decoded_strings'.")
        return await _check_mcp_response_size(ctx, found_and_decoded_results_list, tool_name, limit_info_str_find_decode)

    except Exception as e_find_decode_outer:
        err_msg_find_decode = f"Tool '{tool_name}' encountered an unexpected error during processing: {type(e_find_decode_outer).__name__}: {str(e_find_decode_outer)}"
        await ctx.error(err_msg_find_decode)
        logger.error(f"MCP Tool '{tool_name}': {err_msg_find_decode}", exc_info=True)
        # Return empty list on error, after logging. Size check will pass.
        return await _check_mcp_response_size(ctx, [], tool_name)


@tool_decorator
async def get_current_server_datetime(ctx: Context) -> Dict[str,str]: # Renamed
    """
    Retrieves the current date and time from the server in UTC and the server's local timezone.
    This tool does not depend on a PE file being loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing:
        - "current_utc_datetime_iso": (str) Current UTC date and time in ISO 8601 format.
        - "current_local_datetime_iso": (str) Current server local date and time in ISO 8601 format (includes timezone offset).
        - "server_local_timezone_name": (str) Name of the server's local timezone.
    """
    tool_name = "get_current_server_datetime"
    await ctx.info(f"MCP Tool '{tool_name}': Request for current server datetime.")
    
    now_utc_time = datetime.datetime.now(datetime.timezone.utc)
    now_local_time = datetime.datetime.now().astimezone() # Gets local time with local tz awareness
    
    datetime_info = {
        "current_utc_datetime_iso": now_utc_time.isoformat(),
        "current_local_datetime_iso": now_local_time.isoformat(),
        "server_local_timezone_name": str(now_local_time.tzinfo) # tzinfo.__str__() usually gives timezone name
    }
    # This response is very small, _check_mcp_response_size is more a formality here.
    return await _check_mcp_response_size(ctx, datetime_info, tool_name)


# --- Main Execution Block (`if __name__ == '__main__':`) ---

# Helper functions for main block modularity
def _setup_logging_for_main(is_verbose: bool, mcp_transport_mode: Optional[str]):
    """Configures root logger and uvicorn/mcp loggers based on verbosity and MCP transport."""
    log_level_to_set = logging.DEBUG if is_verbose else logging.INFO
    logging.getLogger().setLevel(log_level_to_set) # Set root logger level
    logger.setLevel(log_level_to_set) # Set our script's logger level

    # Configure MCP SDK logger if it's available and being used
    if MCP_SDK_AVAILABLE: # Check if the real SDK is loaded
        try:
            mcp_logger = logging.getLogger('mcp') # Standard name for MCP SDK's logger
            mcp_logger.setLevel(log_level_to_set)
        except Exception as e_mcp_log: # Should not happen if getLogger is used correctly
            logger.warning(f"Could not configure MCP SDK logger: {e_mcp_log}")

    # If using SSE transport for MCP, uvicorn is involved, configure its logging
    if mcp_transport_mode == "sse":
        try:
            logging.getLogger('uvicorn.error').setLevel(log_level_to_set)
            # Access logs can be noisy, set to WARNING unless verbose, then DEBUG
            uvicorn_access_log_level = logging.DEBUG if is_verbose else logging.WARNING
            logging.getLogger('uvicorn.access').setLevel(uvicorn_access_log_level)
            logging.getLogger('uvicorn').setLevel(log_level_to_set) # General uvicorn logger
            logger.info(f"Uvicorn logging configured for SSE. Access log level: {logging.getLevelName(uvicorn_access_log_level)}")
        except Exception as e_uvicorn_log:
            logger.warning(f"Could not configure uvicorn loggers for SSE transport: {e_uvicorn_log}")
    logger.info(f"Logging initialized. Script logger level: {logging.getLevelName(logger.level)}")


@functools.lru_cache(maxsize=1) # Cache results as paths don't change per run
def _resolve_application_paths_from_args(cli_args: argparse.Namespace) -> Dict[str, Optional[str]]:
    """
    Resolves all necessary file/directory paths from parsed command-line arguments.
    Returns a dictionary of resolved absolute paths (or None if not applicable/provided).
    Uses lru_cache as these paths are fixed once args are parsed.
    """
    paths_dict: Dict[str, Optional[str]] = {}
    
    paths_dict["input_pe_file"] = str(Path(cli_args.input_file).resolve()) if cli_args.input_file else None
    
    # PEiD DB: Use arg if provided, else default. Path object for easier check.
    peid_db_path_obj = Path(cli_args.peid_db).resolve() if cli_args.peid_db else DEFAULT_PEID_DB_PATH.resolve()
    paths_dict["peid_database"] = str(peid_db_path_obj) # Will be created by ensure_peid_db_exists if not present

    # YARA Rules: Resolve if provided, else None.
    paths_dict["yara_rules"] = str(Path(cli_args.yara_rules).resolve()) if cli_args.yara_rules else None
    
    # Capa Rules Directory: Resolve if provided, else None (ensure_capa_rules_exist will handle default download).
    paths_dict["capa_rules_dir_arg"] = str(Path(cli_args.capa_rules_dir).resolve()) if cli_args.capa_rules_dir else None
    
    # Capa Signatures Directory: Resolve if provided, else None.
    paths_dict["capa_sigs_dir_arg"] = str(Path(cli_args.capa_sigs_dir).resolve()) if cli_args.capa_sigs_dir else None
    
    logger.debug(f"Resolved application paths: {paths_dict}")
    return paths_dict


def _run_cli_mode_main(cli_args: argparse.Namespace, 
                       resolved_paths: Dict[str, Optional[str]], 
                       skip_analyses_list: List[str]):
    """Main logic handler for CLI mode."""
    logger.info(f"Running in CLI mode for input file: {resolved_paths.get('input_pe_file')}")
    
    # For CLI mode, capa rules need to be ensured before calling _cli_analyze_and_print_pe
    # if capa is not skipped and is available.
    capa_rules_path_for_cli: Optional[str] = resolved_paths.get("capa_rules_dir_arg")
    if "capa" not in skip_analyses_list and CAPA_AVAILABLE:
        # If user didn't provide a valid capa_rules_dir_arg, or provided None, try to ensure default.
        if not capa_rules_path_for_cli or \
           not (Path(capa_rules_path_for_cli).is_dir() and any(Path(capa_rules_path_for_cli).iterdir())):
            
            logger.info(f"CLI Mode: Capa rules dir '{capa_rules_path_for_cli if capa_rules_path_for_cli else 'not specified by user'}' "
                        "is invalid or empty. Attempting to ensure/download to script-relative default location.")
            default_capa_base_dir_cli = str(SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME) # e.g. ./capa_rules_store
            
            # ensure_capa_rules_exist returns path to the 'rules' subdir, e.g. .../capa_rules_store/rules
            capa_rules_path_for_cli = ensure_capa_rules_exist(default_capa_base_dir_cli, CAPA_RULES_ZIP_URL, cli_args.verbose)
            
            if not capa_rules_path_for_cli:
                logger.error("CLI Mode: Failed to ensure capa rules are available. Capa analysis will likely be skipped or fail if attempted by parser.")
            else:
                logger.info(f"CLI Mode: Successfully ensured capa rules are available at: {capa_rules_path_for_cli}")
    elif "capa" in skip_analyses_list:
         logger.info("CLI Mode: Capa analysis is skipped by user request, not attempting to load/ensure capa rules.")
         capa_rules_path_for_cli = None # Ensure it's None if capa is skipped
    elif not CAPA_AVAILABLE:
         logger.warning("CLI Mode: Capa library (flare-capa) is not available. Capa rule download/check skipped.")
         capa_rules_path_for_cli = None

    try:
        _cli_analyze_and_print_pe(
            filepath_to_analyze=resolved_paths['input_pe_file'], # Should be guaranteed if CLI mode
            resolved_peid_db_path=resolved_paths['peid_database'],
            resolved_yara_rules_path=resolved_paths['yara_rules'],
            resolved_capa_rules_dir=capa_rules_path_for_cli, # Use the path ensured above
            resolved_capa_sigs_dir=resolved_paths['capa_sigs_dir_arg'],
            verbose_output_flag=cli_args.verbose,
            arg_skip_full_peid_scan=cli_args.skip_full_peid_scan,
            arg_peid_scan_all_sigs_heuristically=cli_args.peid_scan_all_sigs_heuristically,
            arg_extract_strings_cli=cli_args.extract_strings,
            arg_min_str_len_cli=cli_args.min_str_len,
            arg_search_strings_cli=cli_args.search_string, # This is a list from argparse
            arg_strings_limit_cli=cli_args.strings_limit,
            arg_hexdump_offset_cli=cli_args.hexdump_offset,
            arg_hexdump_length_cli=cli_args.hexdump_length,
            arg_hexdump_lines_cli=cli_args.hexdump_lines,
            arg_analyses_to_skip_list=skip_analyses_list
        )
    except KeyboardInterrupt: # User pressed Ctrl+C
        safe_print("\n[*] CLI Analysis interrupted by user. Exiting.")
        sys.exit(130) # Common exit code for SIGINT
    except Exception as e_cli_run_fatal:
        # This catches errors raised from _cli_analyze_and_print_pe (e.g., PEFormatError, FileNotFoundError)
        # or any other unexpected critical error during CLI execution.
        safe_print(f"\n[!] A critical error occurred during CLI analysis: {type(e_cli_run_fatal).__name__} - {e_cli_run_fatal}")
        logger.critical("Critical unexpected error during main CLI execution flow.", exc_info=True) # Full traceback to log
        sys.exit(1) # General error exit code
    
    sys.exit(0) # Successful CLI completion


def _run_mcp_server_mode_main(cli_args: argparse.Namespace, 
                              resolved_paths: Dict[str, Optional[str]], 
                              skip_analyses_list: List[str]):
    """Main logic handler for MCP Server mode."""
    global ANALYZED_PE_FILE_PATH, ANALYZED_PE_DATA, PE_OBJECT_FOR_MCP # These are set here

    logger.info(f"Running in MCP Server mode. Input file for pre-analysis: {resolved_paths.get('input_pe_file')}")

    if not MCP_SDK_AVAILABLE: # Double check, though check_and_install_dependencies might have exited
        logger.critical("MCP SDK ('modelcontextprotocol') is not available. Cannot start MCP server mode.")
        logger.critical("Please install it (e.g., 'pip install \"mcp[cli]\"') and re-run.")
        sys.exit(1)

    input_file_for_mcp_preload = resolved_paths.get('input_pe_file')
    if not input_file_for_mcp_preload:
        logger.critical("MCP Server Mode: --input-file was not specified or resolved. Cannot pre-load PE file.")
        sys.exit(1)
    if not Path(input_file_for_mcp_preload).is_file(): # Check if it's actually a file
        logger.critical(f"MCP Server Mode: Input path '{input_file_for_mcp_preload}' is not a file or does not exist.")
        sys.exit(1)

    logger.info(f"MCP Server: Attempting to pre-load and analyze PE file: {input_file_for_mcp_preload}")
    logger.info("The MCP server will become available once this initial analysis is complete (can take time for large files/rulesets).")
    
    temp_pe_obj_for_mcp_preload: Optional[pefile.PE] = None
    try:
        temp_pe_obj_for_mcp_preload = pefile.PE(input_file_for_mcp_preload, fast_load=False)
        ANALYZED_PE_FILE_PATH = input_file_for_mcp_preload # Set global path

        # Perform initial parse. Capa rules/sigs paths from args are used here.
        # _parse_pe_to_dict and its capa helper will handle ensuring capa rules if needed.
        ANALYZED_PE_DATA = _parse_pe_to_dict(
            temp_pe_obj_for_mcp_preload,
            input_file_for_mcp_preload,
            resolved_paths['peid_database'],
            resolved_paths['yara_rules'],
            resolved_paths['capa_rules_dir_arg'], # Pass user arg; _parse_capa_analysis handles default if None/invalid
            resolved_paths['capa_sigs_dir_arg'],   # Pass user arg; _parse_capa_analysis handles default if None/invalid
            cli_args.verbose, # Use main verbose flag for initial parse logging
            cli_args.skip_full_peid_scan,
            cli_args.peid_scan_all_sigs_heuristically,
            analyses_to_skip=skip_analyses_list
        )
        PE_OBJECT_FOR_MCP = temp_pe_obj_for_mcp_preload # Store the successfully opened PE object globally
        logger.info(f"MCP Server: Successfully pre-loaded and analyzed: {input_file_for_mcp_preload}. Server is ready.")

    except Exception as e_mcp_preload:
        logger.critical(f"MCP Server: Failed to pre-load/analyze PE file '{input_file_for_mcp_preload}': {type(e_mcp_preload).__name__} - {str(e_mcp_preload)}", exc_info=cli_args.verbose)
        if temp_pe_obj_for_mcp_preload: # Ensure it's closed if opened before error
            try: temp_pe_obj_for_mcp_preload.close()
            except: pass # Ignore errors on close during error handling
        ANALYZED_PE_FILE_PATH = None # Clear global state on failure
        ANALYZED_PE_DATA = None
        PE_OBJECT_FOR_MCP = None
        logger.error("MCP server will not start due to critical pre-load analysis failure.")
        sys.exit(1) 

    # Configure MCP server settings from args
    mcp_server.settings.host = cli_args.mcp_host
    mcp_server.settings.port = cli_args.mcp_port
    # Log level for MCP server itself is already set by _setup_logging_for_main
    # mcp_server.settings.log_level = logging.getLevelName(logger.level).lower() # Redundant if mcp logger respects root

    if cli_args.mcp_transport == "sse":
        logger.info(f"Starting MCP server (SSE transport) on http://{mcp_server.settings.host}:{mcp_server.settings.port}")
    else: # stdio
        logger.info(f"Starting MCP server (stdio transport). Listening for requests on stdin/stdout.")

    server_runtime_exception = None
    try:
        mcp_server.run(transport=cli_args.mcp_transport) # This blocks until server stops
    except KeyboardInterrupt:
        logger.info("MCP Server stopped by user (KeyboardInterrupt).")
    except Exception as e_mcp_runtime:
        logger.critical(f"MCP Server encountered an unhandled runtime error: {type(e_mcp_runtime).__name__} - {str(e_mcp_runtime)}", exc_info=True)
        server_runtime_exception = e_mcp_runtime
    finally:
        if PE_OBJECT_FOR_MCP: # Ensure global PE object is closed on server exit
            try:
                PE_OBJECT_FOR_MCP.close()
                logger.info("MCP Server: Closed pre-loaded PE object upon server exit.")
            except Exception as e_close_final:
                logger.warning(f"MCP Server: Error closing global PE object on exit: {e_close_final}")
        
        logger.info("MCP Server has shut down.")
        sys.exit(1 if server_runtime_exception else 0) # Exit with error if server crashed


if __name__ == '__main__':
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Comprehensive PE File Analyzer (PeMCP). Analyzes PE files in CLI mode or runs as an MCP server.",
        formatter_class=argparse.RawTextHelpFormatter # Allows for better formatting in help text
    )
    # Required argument for both modes
    parser.add_argument(
        "--input-file", type=str, required=True, 
        help="REQUIRED: Path to the PE file. Used for analysis in CLI mode, or for pre-analysis at server startup in MCP mode."
    )
    # Optional arguments for databases and rules
    parser.add_argument(
        "-d", "--db", dest="peid_db", default=None,
        help=f"Path to PEiD userdb.txt. If not specified, defaults to a script-relative '{DEFAULT_PEID_DB_PATH.name}'. "
             "The script will attempt to download it from GitHub if not found at the default or specified path."
    )
    parser.add_argument(
        "-y", "--yara-rules", dest="yara_rules", default=None,
        help="Path to a YARA rule file or a directory containing .yar/.yara rule files."
    )
    parser.add_argument(
        "--capa-rules-dir", default=None,
        help=f"Directory containing capa rule files (e.g., the 'rules' subdir from capa-rules release). "
             f"If not provided, invalid, or empty, the script attempts to download and use rules from "
             f"'{CAPA_RULES_ZIP_URL}' into a script-relative '{CAPA_RULES_DEFAULT_DIR_NAME}/{CAPA_RULES_SUBDIR_NAME}'."
    )
    parser.add_argument(
        "--capa-sigs-dir", default=None,
        help="Directory containing capa library identification signature files (e.g., *.sig files). Optional. "
             "If not provided, the script attempts to find a local 'capa_sigs' directory or one near the capa rules store. "
             "If none found, capa may use its internal default or load no library signatures."
    )
    # General options
    parser.add_argument(
        "--skip-capa", action="store_true", 
        help="Skip capa capability analysis entirely in either CLI or MCP pre-load."
    )
    # Add other skip flags if needed, e.g., --skip-yara, --skip-peid
    parser.add_argument(
        "-v", "--verbose", action="store_true", 
        help="Enable verbose output for CLI mode and more detailed server-side logging for MCP mode."
    )
    # PEiD specific scan options
    parser.add_argument(
        "--skip-full-peid-scan", action="store_true",
        help="For PEiD analysis: Skip full file heuristic scan, only scan the entry point area."
    )
    parser.add_argument(
        "--psah", "--peid-scan-all-sigs-heuristically", action="store_true", dest="peid_scan_all_sigs_heuristically",
        help="For PEiD full heuristic scan: Use ALL signatures (including ep_only=true ones) heuristically across sections, "
             "not just non-EP_only signatures."
    )

    # CLI Mode Specific Options
    cli_group = parser.add_argument_group('CLI Mode Specific Options (these are ignored if --mcp-server is used)')
    cli_group.add_argument("--extract-strings", action="store_true", help="Extract and print all printable ASCII strings from the PE file.")
    cli_group.add_argument("--min-str-len", type=int, default=5, help="Minimum length for extracted strings (default: 5).")
    cli_group.add_argument("--search-string", action="append", help="String to search for within the PE file (case-sensitive, ASCII). Multiple uses allowed.")
    cli_group.add_argument("--strings-limit", type=int, default=100, help="Limit for the number of strings displayed (for extraction and search results per term) (default: 100).")
    cli_group.add_argument("--hexdump-offset", type=lambda x: int(x,0), help="Hex dump start offset (e.g., 0x1000 or 4096). Requires --hexdump-length.")
    cli_group.add_argument("--hexdump-length", type=int, help="Hex dump length in bytes. Requires --hexdump-offset.")
    cli_group.add_argument("--hexdump-lines", type=int, default=16, help="Maximum number of lines to display for hex dump (default: 16).")

    # MCP Server Mode Specific Options
    mcp_group = parser.add_argument_group('MCP Server Mode Specific Options')
    mcp_group.add_argument("--mcp-server", action="store_true", help="Run in MCP server mode. The --input-file is pre-analyzed.")
    mcp_group.add_argument("--mcp-host", type=str, default="127.0.0.1", help="MCP server host (default: 127.0.0.1).")
    mcp_group.add_argument("--mcp-port", type=int, default=8082, help="MCP server port (default: 8082).")
    mcp_group.add_argument("--mcp-transport", type=str, default="stdio", choices=["stdio", "sse"], help="MCP transport protocol (stdio or sse for HTTP Server-Sent Events) (default: stdio).")
    
    args = parser.parse_args()

    # --- Initial Setup Steps ---
    # 1. Setup logging (based on verbosity and MCP transport for uvicorn)
    _setup_logging_for_main(args.verbose, args.mcp_transport if args.mcp_server else None)

    # 2. Initialize and log status of optional dependencies (sets global flags like CAPA_AVAILABLE)
    # This happens after pefile check (at top) and after basic logging is up.
    _initialize_and_log_dependency_statuses()

    # 3. Check for missing dependencies and offer installation (uses global flags set above)
    # Exits if critical dependencies for the chosen mode are missing and not installed.
    check_and_install_dependencies(is_mcp_server_mode_arg=args.mcp_server)
    # If check_and_install_dependencies prompted for install and any were installed, it would have exited.
    # If it returns, either all critical deps are met, or user chose not to install non-critical ones.

    # 4. Resolve all application paths from arguments
    # This is cached, so calling it multiple times (e.g., in CLI and MCP mode setup if structured that way) is fine.
    resolved_app_paths = _resolve_application_paths_from_args(args)
    if not resolved_app_paths.get("input_pe_file"): # Critical for both modes
        logger.critical("No input PE file specified or resolved. Exiting.")
        sys.exit(1)


    # 5. Prepare list of analyses to skip based on command-line arguments
    analyses_to_skip_from_args: List[str] = []
    if args.skip_capa:
        analyses_to_skip_from_args.append("capa")
        logger.info("User requested to skip Capa analysis via --skip-capa argument.")
    # Add more --skip-X flags here and append to analyses_to_skip_from_args if needed

    # --- Mode Selection and Execution ---
    if args.mcp_server:
        _run_mcp_server_mode_main(args, resolved_app_paths, analyses_to_skip_from_args)
    else: # Default to CLI mode if --mcp-server is not specified
        _run_cli_mode_main(args, resolved_app_paths, analyses_to_skip_from_args)

    # Should not be reached if modes call sys.exit(), but as a fallback.
    sys.exit(0) 
