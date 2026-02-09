"""
Central configuration, imports, availability flags, and constants.

All optional library imports and their availability flags are managed here.
Other modules import what they need from this module.
"""
import datetime
import os
import sys
import struct
import re
import concurrent.futures
import hashlib
import warnings
import json
import logging
import io
import asyncio
import importlib.util
import subprocess
import mmap
import zipfile
import shutil
import collections
import copy
import base64
import codecs
import urllib.parse
import binascii
import uuid
import threading
import time

from pathlib import Path

# Third-party (always available)
import networkx as nx

from typing import Dict, Any, Optional, List, Tuple, Set, Union, Type

from pemcp.state import AnalyzerState
from pemcp.user_config import get_config_value

# --- Global State Instance ---
state = AnalyzerState()

# --- Ensure pefile is available (Critical Dependency) ---
try:
    import pefile
except ImportError:
    print("[!] CRITICAL ERROR: The 'pefile' library is not found.", file=sys.stderr)
    print("[!] This library is essential for the script to function.", file=sys.stderr)
    print("[!] Install it with: pip install pefile", file=sys.stderr)
    sys.exit(1)

DATA_DIR = Path(os.getenv("PEMCP_DATA_DIR", Path(__file__).resolve().parent.parent))

# --- VirusTotal API Configuration ---
VT_API_KEY = get_config_value("vt_api_key")
VT_API_URL_FILE_REPORT = "https://www.virustotal.com/api/v3/files/"

# --- Optional Library Imports & Availability Flags ---
CRYPTOGRAPHY_AVAILABLE = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    pass

REQUESTS_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    pass

# --- Corrected Signify Import ---
SIGNIFY_AVAILABLE = False
SIGNIFY_IMPORT_ERROR = None
try:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
    SIGNIFY_AVAILABLE = True
except ImportError as e:
    SIGNIFY_IMPORT_ERROR = str(e)
    SIGNIFY_AVAILABLE = False
    print(f"[!] Signify Import Error: {e}", file=sys.stderr)

YARA_AVAILABLE = False
YARA_IMPORT_ERROR = None
try:
    import yara
    YARA_AVAILABLE = True
except ImportError as e:
    YARA_IMPORT_ERROR = e

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger("PeMCP")

RAPIDFUZZ_AVAILABLE = False
RAPIDFUZZ_IMPORT_ERROR = None
try:
    from rapidfuzz import fuzz
    RAPIDFUZZ_AVAILABLE = True
except ImportError as e:
    RAPIDFUZZ_AVAILABLE = False
    RAPIDFUZZ_IMPORT_ERROR = str(e)

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

# --- Constants for MCP Response Size Limit ---
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
MIN_STR_LEN_FALLBACK_FLOSS = 4
class DebugLevelFallbackFloss: NONE, DEFAULT, TRACE, SUPERTRACE = 0, 1, 2, 3
class StringTypeFallbackFloss: STATIC, STACK, TIGHT, DECODED = "static", "stack", "tight", "decoded"

FLOSS_MIN_LENGTH_DEFAULT = MIN_STR_LEN_FALLBACK_FLOSS
Actual_DebugLevel_Floss: Type = DebugLevelFallbackFloss
Actual_StringType_Floss: Type = StringTypeFallbackFloss
Floss_ColorFormatter_Class: Type = logging.Formatter
FLOSS_TRACE_LEVEL_CONST = logging.DEBUG

FLOSS_SETUP_OK = False
FLOSS_ANALYSIS_OK = False
FLOSS_AVAILABLE = False
FLOSS_IMPORT_ERROR_SETUP = None
FLOSS_IMPORT_ERROR_ANALYSIS = None

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

if FLOSS_SETUP_OK:
    try:
        import viv_utils
        from vivisect import VivWorkspace
        from floss.utils import get_static_strings, set_vivisect_log_level, get_imagebase
        from floss.identify import (
            find_decoding_function_features, get_top_functions, get_function_fvas,
            get_tight_function_fvas, append_unique, get_functions_with_tightloops
        )
        from floss.stackstrings import extract_stackstrings
        from floss.tightstrings import extract_tightstrings
        from floss.string_decoder import decode_strings
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

FLOSS_LOGGERS_LIST = [
    "floss", "floss.utils", "floss.identify", "floss.stackstrings",
    "floss.tightstrings", "floss.string_decoder", "EmulatorDriver", "Monitor",
    "envi", "envi.codeflow", "vtrace", "vtrace.platforms.win32",
    "vivisect", "vivisect.parsers.pe", "viv_utils.emulator_drivers",
]
# --- END FLOSS IMPORT SECTION ---

STRINGSIFTER_AVAILABLE = False
STRINGSIFTER_IMPORT_ERROR = None
try:
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
    class MockSettings: host = "127.0.0.1"; port = 8081; log_level = "INFO"
    class MockMCP:
        def __init__(self, name, description=""): self.name = name; self.description = description; self.app = object(); self.settings = MockSettings(); self._run_called_with_transport = None
        def tool(self): decorator = lambda func: func; return decorator
        def run(self, transport: str = "stdio"): print(f"MockMCP '{self.name}' run method called with transport='{transport}'.")
    FastMCP = MockMCP  # type: ignore
    class Context:  # type: ignore
        async def info(self, msg): print(f"(mock ctx info): {msg}")
        async def error(self, msg): print(f"(mock ctx error): {msg}")
        async def warning(self, msg): print(f"(mock ctx warning): {msg}")

# --- Angr Integration ---
ANGR_AVAILABLE = False
try:
    import angr
    import angr.analyses.decompiler
    ANGR_AVAILABLE = True
    logger.info("Angr library found. Advanced binary analysis (Decompilation, Symbolic Execution) enabled.")
except ImportError:
    ANGR_AVAILABLE = False
    logger.warning("Angr library not found. Advanced binary analysis tools will be unavailable.")

# --- Constants ---
PEID_USERDB_URL = "https://raw.githubusercontent.com/JameZUK/PeMCP/refs/heads/main/userdb.txt"
DEFAULT_PEID_DB_PATH = DATA_DIR / "userdb.txt"

CAPA_RULES_ZIP_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.1.0.zip"
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
    ("rapidfuzz", "rapidfuzz", "RapidFuzz (for fuzzy string matching)", False),
    ("viv_utils", "vivisect", "Vivisect & Viv-Utils (for FLOSS analysis backend)", False),
    ("mcp.server", "mcp[cli]", "MCP SDK (for MCP server mode)", True),
    ("angr", "angr", "Angr (for binary decompilation & solving)", False)
]

# --- Availability Logging ---
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
if RAPIDFUZZ_AVAILABLE: logger.info("RapidFuzz library found. Fuzzy string search will be available.")
else: logger.warning(f"RapidFuzz library not found. Fuzzy search will be skipped. Import error: {RAPIDFUZZ_IMPORT_ERROR}")
