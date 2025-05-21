    # PeMCP Toolkit - Comprehensive Portable Executable Analysis Suite

    The PeMCP Toolkit is a Python-based script designed for in-depth analysis of Portable Executable (PE) files. It provides functionalities for parsing PE structures, examining raw file content, extracting embedded information, and performing advanced heuristic analysis. The script can be run directly from the command-line for interactive analysis or as a Model-Context-Protocol (MCP) server for programmatic integration. This toolkit is invaluable for malware analysis, reverse engineering, digital forensics, and software auditing.

    ## Overview of PeMCP Functionality

    The PeMCP Toolkit (`PeMCP.py`) offers two primary modes of operation:

    1.  **Command-Line Interface (CLI) Mode:**
        * **Description:** Performs a comprehensive static analysis of a specified PE file and prints a detailed report to the console. Includes options for PEiD-like signature scanning, YARA scanning, Capa capability detection, string extraction/searching, and hex dumping of file content based on command-line flags.
        * **Invocation:** `python PeMCP.py --input-file <file_path> [options]`

    2.  **Model-Context-Protocol (MCP) Server Mode:**
        * **Description:** Runs as an MCP server, pre-analyzing a single PE file specified by `--input-file` at startup. All MCP tools then operate on this pre-loaded file's data. The server will only become fully available after the initial analysis (including potentially long-running components like Capa) completes successfully.
        * **Invocation:** `python PeMCP.py --mcp-server --input-file <file_path> [server_options]`

    ### Core Analysis Capabilities:

    Regardless of the mode, PeMCP leverages `pefile` for deep PE structure parsing and integrates several analysis techniques:

    * Detailed PE Structure Parsing: DOS Header, NT Headers (File Header, Optional Header), Data Directories, Section Table.
    * Hashing: MD5, SHA1, SHA256 for the full file and individual sections. Includes an integrated pure-Python **SSDeep** for fuzzy hashing.
    * Import/Export Analysis: Detailed listing of imported DLLs and functions (including delay-loaded imports) and exported functions.
    * Resource Analysis: Summary of embedded resources.
    * Signature-Based Detection:
        * **PEiD Signatures:** Matches packer/compiler signatures using a `userdb.txt` (downloaded automatically if `requests` is installed).
        * **YARA Scanning:** If `yara-python` is installed and rule files are provided.
    * Capability Analysis:
        * **Capa:** If `flare-capa` is installed and rule/signature files are available, identifies program capabilities.
    * Other PE Features: Rich Header decoding, Version Information, Debug Information (PDB paths), TLS Callbacks, Load Configuration, COM Descriptor (for .NET), Overlay data, Base Relocations, Bound Imports, Exception Data, COFF Symbols, and Checksum Verification.
    * String & Hex Utilities (CLI Mode): Options to extract strings, search for specific strings, and perform hex dumps are available as command-line flags in CLI mode.
    * MCP Tools (Server Mode): A comprehensive set of tools to access parsed data, re-trigger analyses on the pre-loaded file, and perform utility functions (see MCP Server Mode section for details).

    ---

    ## 1. CLI Mode Operation

    This is the primary mode for direct, command-line based analysis of a single PE file.

    ### Key Analysis Sections in CLI Output:

    * File Hashes (MD5, SHA1, SHA256, SSDeep)
    * DOS Header details
    * NT Headers (File Header, Optional Header) details, including PE type (32/64-bit) and characteristics
    * Data Directories (listing RVA and Size for each)
    * Section Table (Name, Virtual Address/Size, Raw Data Pointer/Size, Characteristics, Entropy, MD5/SHA1/SHA256 of section data)
    * Import Table (DLLs and their imported functions/ordinals)
    * Export Table (Exported function names, ordinals, addresses, forwarders)
    * Resource Directory Summary
    * Version Information (from version resources)
    * Debug Information (including PDB path if present)
    * Digital Signatures (Authenticode, with certificate details via `cryptography` and validation via `signify`)
    * PEiD Signature Matches
    * YARA Scan Results (if rules provided)
    * Capa Capability Analysis (if rules/signatures provided)
    * Rich Header information
    * Delay-Load Imports, TLS Information, Load Configuration, COM Descriptor, Overlay Data, Base Relocations, Bound Imports, Exception Data, COFF Symbol Table, Checksum Verification.
    * PEFile Warnings

    ### CLI Mode Command-Line Usage:

    ```bash
    python PeMCP.py --input-file <file_path> [options]
    ```

    * **`--input-file <file_path>`**: (Required) Path to the PE file to analyze.
    * **`-v, --verbose`**: Enable more detailed output, including verbose Capa matches and section data samples.
    * **`--db PATH_TO_USERDB`**: Custom path to PEiD `userdb.txt`. Defaults to `./userdb.txt` in the script's directory (attempts download if missing and `requests` is installed).
    * **`-y RULES_PATH, --yara-rules RULES_PATH`**: Path to a YARA rule file or a directory containing YARA rules.
    * **`--capa-rules-dir PATH_TO_CAPA_RULES`**: Directory containing Capa rule files. If not specified, the script attempts to download them to a default location (`./capa_rules_store/rules/`) if `requests` and `flare-capa` are available.
    * **`--capa-sigs-dir PATH_TO_CAPA_SIGS`**: Directory for Capa library function signature files (`*.sig`). Optional; if not provided, script-relative `./capa_sigs` is checked or Capa proceeds without library function identification.
    * **`--skip-full-peid-scan`**: Limits PEiD scan to the entry point only.
    * **`--psah`, `--peid-scan-all-sigs-heuristically`**: Uses all PEiD signatures (including non-EP_only) for heuristic scanning across executable sections.

    #### Additional CLI Functionalities (Flags for `PeMCP.py`):

    * **String Extraction:**
        * `--extract-strings`: Enables string extraction from the entire file.
        * `--min-str-len LENGTH`: Sets the minimum length for extracted strings (default: 5).
        * `--strings-limit COUNT`: Maximum number of strings to display (default: 100).
    * **Specific String Search:**
        * `--search-string "TEXT_TO_FIND"`: Search for one or more specific ASCII strings. Use the flag multiple times for multiple strings.
        * *(Uses `--strings-limit` to cap displayed occurrences per search term)*.
    * **Hex Dump:**
        * `--hexdump-offset OFFSET`: Hexadecimal (e.g., `0x1000`) or decimal offset to start the dump. Requires `--hexdump-length`.
        * `--hexdump-length LENGTH`: Number of bytes to dump. Requires `--hexdump-offset`.
        * `--hexdump-lines COUNT`: Maximum number of lines for the hex dump output (default: 16).

    *For a complete list of current command-line options, run:*
    ```bash
    python PeMCP.py --help
    ```

    ---

    ## 2. MCP Server Mode Operation

    When run with the `--mcp-server` flag, `PeMCP.py` starts an MCP server that pre-analyzes the file specified by `--input-file`. All tools then operate on this pre-loaded file.

    ### MCP Server Key Characteristics:

    * **Single File Focus:** The server pre-analyzes one PE file specified by `--input-file` at startup. All subsequent tool calls operate on this single pre-loaded file's data.
    * **Startup Analysis:** A full analysis (including PEiD, YARA, and Capa, based on available dependencies and provided rule/signature paths) is performed on the `--input-file` *before* the MCP server starts accepting connections. If this initial analysis fails, the script will log an error and exit.
    * **Transport Protocols:** Supports `stdio` and `sse` (Server-Sent Events) for communication.

    ### MCP Server Command-Line Usage:

    ```bash
    python PeMCP.py --mcp-server --input-file <path_to_pe_file> [server_options] [analysis_dependency_paths]
    ```

    * **`--mcp-server`**: Activates MCP server mode.
    * **`--input-file <path_to_pe_file>`**: (Required in MCP mode) Path to the PE file to be pre-analyzed and served.
    * **`--mcp-host HOST`**: Host for SSE server (default: `127.0.0.1`).
    * **`--mcp-port PORT`**: Port for SSE server (default: `8082`).
    * **`--mcp-transport TRANSPORT`**: `stdio` or `sse` (default: `stdio`).
    * Other options like `--db`, `--yara-rules`, `--capa-rules-dir`, `--capa-sigs-dir`, `--verbose`, etc., are used for the initial analysis and can be overridden by the `reanalyze_loaded_pe_file` tool.

    ### Core MCP Tools:

    *(Note: Many tools returning collections or large data now have a **mandatory `limit` parameter** to control response size. This limit must be a positive integer.)*

    * **`reanalyze_loaded_pe_file`**:
        * **Description:** Re-triggers analysis on the PE file pre-loaded at server startup. This is useful if external resources like YARA rules or PEiD databases have been updated.
        * **Arguments:** `analyses_to_skip` (Optional List\[str]): Analyses to skip (e.g., `["peid", "yara", "capa"]`). Paths for PEiD DB, YARA rules, Capa rules/signatures (to override startup defaults for this specific re-analysis), `verbose_mcp_output`, `skip_full_peid_scan`, `peid_scan_all_sigs_heuristically`.
    * **`get_analyzed_file_summary`**:
        * **Description:** Retrieves a high-level summary of the pre-loaded PE file.
        * **Argument:** `limit` (int, Mandatory).
    * **`get_full_analysis_results`**:
        * **Description:** Retrieves the complete analysis dictionary for the pre-loaded file.
        * **Argument:** `limit` (int, Mandatory).
    * **`get_<key>_info` Tools (e.g., `get_sections_info`, `get_imports_info`):**
        * **Description:** Dynamically generated tools to retrieve specific parts of the analysis data (e.g., 'dos_header', 'sections', 'yara_matches').
        * **Arguments:** `limit` (int, Mandatory), `offset` (Optional int, default 0 for list-based data).
    * **`get_capa_analysis_info`**:
        * **Description:** Retrieves detailed Capa capability analysis results with filtering and pagination.
        * **Arguments:** `limit` (int, Mandatory), and various optional filters.
    * **`extract_strings_from_binary`**:
        * **Description:** Extracts strings from the pre-loaded file.
        * **Arguments:** `limit` (int, Mandatory), `min_length` (Optional int).
    * **`search_for_specific_strings`**:
        * **Description:** Searches for specific strings in the pre-loaded file.
        * **Arguments:** `search_terms` (List\[str]), `limit_per_term` (Optional int).
    * **`get_hex_dump`**:
        * **Description:** Provides a hex dump from the pre-loaded file.
        * **Arguments:** `start_offset` (int), `length` (int), `bytes_per_line` (Optional int), `limit_lines` (Optional int).
    * **Utility Tools:**
        * `get_current_datetime`
        * `deobfuscate_base64`
        * `deobfuscate_xor_single_byte`
        * `is_mostly_printable_ascii`

    ---

    ## General Toolkit Information

    ### Requirements

    * **Python 3.7+**
    * **`pefile`**: Core library for PE parsing. (The script will offer to install this via pip if missing and run in an interactive terminal).
    * **Optional Libraries** (The script checks for these at startup and may prompt for installation if run interactively):
        * **`requests`**: For downloading the PEiD database and Capa rules if they are not found locally.
        * **`cryptography`**: For advanced parsing and display of digital signature certificate details.
        * **`signify`**: For validation of Authenticode digital signatures.
        * **`yara-python`**: Required for YARA scanning functionality.
        * **`flare-capa`**: Required for Capa program capability analysis.
        * **`mcp[cli]`** (Model Context Protocol SDK): Required **only** for running in `--mcp-server` mode.
    * **SSDeep Functionality**: Provided by an **integrated pure-Python implementation**; no external `ssdeep` library or C binary is required.
    * **External Data Files (Optional, but recommended for full functionality):**
        * **`userdb.txt`**: PEiD signature database. The script will attempt to download it to the script's directory if `requests` is available and the file is not found at the default path (`./userdb.txt`) or specified path.
        * **Capa Rules**: If `flare-capa` and `requests` are installed, and rules are not found at the path specified by `--capa-rules-dir` (or the default path `./capa_rules_store/rules/`), the script will attempt to download and extract them.
        * **Capa Signatures**: For library function identification by Capa. If you have them, place them in a directory (e.g., `./capa_sigs`) and specify this path using `--capa-sigs-dir`.

    ### Installation

    1.  **Clone the repository or download `PeMCP.py`:**
        ```bash
        git clone <your_repository_url> # Replace with your actual repository URL
        cd PeMCP
        ```
    2.  **Install `pefile` (critical dependency):**
        If you run the script and `pefile` is missing in an interactive environment, it will offer to install it. Otherwise, you can install it manually:
        ```bash
        pip install pefile
        ```
    3.  **Install Optional Dependencies (Recommended for full functionality):**
        The script will notify you about missing optional dependencies. You can install them individually or all at once:
        ```bash
        pip install requests cryptography signify yara-python flare-capa "mcp[cli]"
        ```
        *(Note: `mcp[cli]` is only necessary if you intend to use the `--mcp-server` mode.)*
    4.  **Data Files:**
        * **PEiD Database (`userdb.txt`):** If not found at the default path (`./userdb.txt` relative to the script) or a path specified with `--db`, the script will attempt to download it (requires `requests`).
        * **Capa Rules:** If `flare-capa` and `requests` are installed, and rules are not found at the path specified by `--capa-rules-dir` (or the default path `./capa_rules_store/rules/`), the script will attempt to download and extract them.
        * **Capa Signatures:** For library function identification by Capa. If you have them, place them in a directory (e.g., `./capa_sigs`) and specify this path using `--capa-sigs-dir`.

    ### How It Works (General Principles)

    * **PE Analysis:** Primarily uses the `pefile` library for parsing PE structures. Hashes are calculated using `hashlib` (MD5, SHA1, SHA256) and the integrated `SSDeep` class for fuzzy hashes. Custom logic is implemented for parsing specific structures like the Rich Header.
    * **PEiD Scan:** Employs a custom parser for the `userdb.txt` format and applies regex-compiled signatures to the PE file's entry point and executable sections.
    * **YARA/Capa Integration:** Leverages the respective Python libraries (`yara-python`, `flare-capa`) through their Python APIs when these libraries are installed and their rule/signature paths are provided.
    * **String/Hex Utilities (CLI):** Implemented using standard Python file I/O and string manipulation, available as flags during a CLI analysis run.
    * **MCP Server:** If `PeMCP.py` is run with the `--mcp-server` flag, it uses the `modelcontextprotocol` library to expose its analysis tools.

    ### Limitations

    * **Static Analysis Only:** The script performs static analysis and does not execute the PE files.
    * **Advanced Obfuscation/Packing:** The effectiveness of the analysis on heavily obfuscated or packed files depends on the capabilities of the underlying `pefile` library and other integrated tools to handle the outer layers. Analysis is generally performed on the file as-is.
    * **Authenticode Full Chain Validation:** While `signify` provides robust signature validation, comprehensive trust chain validation might depend on the system's certificate stores and is not fully managed by this script.

    ### Contributing

    Contributions are welcome! Please follow standard GitHub practices:
    1.  Fork the repository.
    2.  Create a feature branch (`git checkout -b feature/YourAmazingFeature`).
    3.  Commit your changes (`git commit -m 'Add YourAmazingFeature'`).
    4.  Push to the branch (`git push origin feature/YourAmazingFeature`).
    5.  Open a Pull Request.

    ### License

    *(Please update this section with your chosen license, e.g., MIT, Apache 2.0, or specify if it's proprietary.)*
    Example: Distributed under the MIT License. See `LICENSE.txt` for more information.

    ### Disclaimer

    This toolkit is provided "as-is" for educational and research purposes only. Users are solely responsible for ensuring they have proper authorization before analyzing any files with this tool. The author(s) and contributors are not liable for any misuse or damage caused by this software.
