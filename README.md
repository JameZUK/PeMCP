# **PeMCP Toolkit - Comprehensive Portable Executable Analysis Suite**

The PeMCP Toolkit is a Python-based script designed for in-depth analysis of Portable Executable (PE) files. It provides functionalities for parsing PE structures, examining raw file content, extracting embedded information, and performing advanced heuristic analysis. The script can be run directly from the command-line for interactive analysis or as a Model-Context-Protocol (MCP) server for programmatic integration. This toolkit is invaluable for malware analysis, reverse engineering, digital forensics, and software auditing.

## **Prerequisites and Installation**

1.  **Python 3.7+**: Ensure you have a compatible version of Python installed.
2.  **Clone the Repository**:
    ```bash
    git clone [https://github.com/YOUR_USERNAME/PeMCP/](https://github.com/YOUR_USERNAME/PeMCP/) # Replace with your actual repository URL
    cd PeMCP
    ```
3.  **Install Dependencies**: This project uses a `requirements.txt` file to manage all necessary libraries. Install them with a single command:
    ```bash
    pip install -r requirements.txt
    ```
    This will automatically install all core and optional dependencies, including:
    * `pefile`: The core library for parsing the PE file structure.
    * `cryptography`: For advanced parsing of digital signature certificate details.
    * `requests`: For automatically downloading the PEiD database, Capa rules, and for VirusTotal queries.
    * `signify`: For validation of Authenticode digital signatures.
    * `yara-python`: Required for all YARA scanning functionality.
    * `flare-capa`: Required for Capa program capability analysis.
    * `flare-floss`: Required for advanced string extraction features.
    * `vivisect`: A dependency for `flare-floss` analysis.
    * `mcp[cli]`: Required **only** for running in `--mcp-server` mode.

4.  **Data Files**:
    * **PEiD Database (`userdb.txt`)**: Handled automatically by the script if `requests` is installed.
    * **Capa Rules**: Handled automatically by the script if `flare-capa` and `requests` are installed.

## **Overview of PeMCP Functionality**

The PeMCP Toolkit (`PeMCP.py`) offers two primary modes of operation:

1.  **Command-Line Interface (CLI) Mode**:
    * **Description**: Performs a comprehensive static analysis of a specified PE file and prints a detailed report to the console. It supports PEiD-like signature scanning, YARA scanning, Capa capability detection, advanced FLOSS string extraction, general string searching, and hex dumping.
    * **Invocation**:
        ```bash
        python PeMCP.py --input-file <file_path> [options]
        ```

2.  **Model-Context-Protocol (MCP) Server Mode**:
    * **Description**: Runs as an MCP server, pre-analyzing a single PE file specified by `--input-file` at startup. All MCP tools then operate on this pre-loaded file's data. The server will only become fully available after the initial analysis completes successfully.
    * **Invocation**:
        ```bash
        python PeMCP.py --mcp-server --input-file <file_path> [server_options]
        ```

### **Core Analysis Capabilities**:

* **Detailed PE Structure Parsing**: DOS Header, NT Headers (File Header, Optional Header), Data Directories, Section Table.
* **Hashing**: MD5, SHA1, SHA256 for the full file and individual sections. Includes an integrated pure-Python **SSDeep** for fuzzy hashing.
* **Import/Export Analysis**: Detailed listing of imported DLLs and functions (including delay-loaded imports) and exported functions.
* **Resource Analysis**: Summary of embedded resources.
* **Signature-Based Detection**:
    * **PEiD Signatures**: Matches packer/compiler signatures using `userdb.txt`.
    * **YARA Scanning**: If `yara-python` is installed and rule files are provided.
* **Capability and String Analysis**:
    * **Capa**: If `flare-capa` is installed, it identifies program capabilities.
    * **FLOSS**: If `flare-floss` is installed, it performs advanced string extraction (static, stack, tight, and decoded).
* **Other PE Features**: Rich Header decoding, Version Information, Digital Signatures, Debug Information (PDB paths), TLS Callbacks, Load Configuration, and more.
* **String & Hex Utilities (CLI Mode)**: Options to extract strings, search for specific strings, and perform hex dumps are available as command-line flags.

## **CLI Mode Command-Line Usage**

The primary mode for direct, command-line based analysis of a single PE file.

**Full Usage:**
```bash
python PeMCP.py --input-file <file_path> [options]
* `--input-file <file_path>`: **(Required)** Path to the PE file to analyze. [cite: 24]
* `-v, --verbose`: Enable more detailed output. [cite: 25]
* `-d, --db <PATH_TO_USERDB>`: Custom path to PEiD `userdb.txt`. [cite: 26]
* `-y, --yara-rules <RULES_PATH>`: Path to a YARA rule file or directory. [cite: 28]
* `--capa-rules-dir <PATH>`: Directory containing Capa rule files. [cite: 29]
* `--capa-sigs-dir <PATH>`: Directory for Capa library identification signature files.
* `--skip-capa`: Skip Capa capability analysis entirely. [cite: 30]
* `--skip-floss`: Skip FLOSS advanced string analysis entirely.
* `--skip-full-peid-scan`: Limits PEiD scan to the entry point only. [cite: 31]

#### **FLOSS Specific Options (CLI):**
* `--floss-min-length <LENGTH>`: Minimum string length for FLOSS. [cite: 863]
* `--floss-format <FORMAT>`: File format hint for FLOSS (e.g., `pe`, `sc32`, `sc64`). [cite: 864]
* `--floss-no-static`, `--floss-no-stack`, etc.: Disable specific FLOSS string extraction methods. [cite: 874]
* `--floss-only-static`, `--floss-only-stack`, etc.: Only run a specific FLOSS extraction method. [cite: 874]

#### **String & Hex Utilities (CLI):**
* `--extract-strings`: Enables string extraction from the entire file. [cite: 33, 891]
* `--min-str-len <LENGTH>`: Sets the minimum length for extracted strings (default: 5). [cite: 34, 891]
* `--search-string "TEXT"`: Search for one or more specific ASCII strings. [cite: 36, 891]
* `--hexdump-offset <OFFSET>`: Hexadecimal or decimal offset to start a hex dump. [cite: 37, 891]
* `--hexdump-length <LENGTH>`: Number of bytes to dump. [cite: 38, 891]
```
*For a complete and current list of all command-line options, run:*
```bash
python PeMCP.py --help
## **MCP Server Mode Operation**
```
When run with `--mcp-server`, the script pre-analyzes the specified input file and starts an MCP server, allowing programmatic access to analysis results via a rich set of tools. This mode is ideal for integration with other systems.

* **Single File Focus**: The server pre-analyzes one PE file at startup, and all tool calls operate on this file's data. 
* **Comprehensive Tools**: A large set of tools is available to retrieve specific parts of the analysis (e.g., `get_sections_info`, `get_imports_info`), re-trigger analysis, search for strings, get hex dumps, and even query VirusTotal for the loaded file's hash. 

## **How It Works (General Principles)**

* **PE Analysis**: Primarily uses the `pefile` library for parsing PE structures. [cite: 92] Hashes are calculated using `hashlib` and the integrated `SSDeep` class.
* **Signature Scanning**: Employs a custom parser for the `userdb.txt` format and applies regex-compiled signatures for PEiD scanning.
* **External Tool Integration**: Leverages `yara-python`, `flare-capa`, and `flare-floss` through their Python APIs.
* **MCP Server**: Uses the `modelcontextprotocol` library to expose its analysis tools. 

## **Limitations**

* **Static Analysis Only**: The script performs static analysis and does not execute the PE files. 
* **Advanced Obfuscation/Packing**: Effectiveness on heavily obfuscated files depends on the capabilities of `pefile` and the other integrated tools. 
* **Authenticode Full Chain Validation**: Relies on `signify`; comprehensive trust chain validation might depend on system certificate stores. 

## **Contributing**

Contributions are welcome! Please follow standard GitHub practices:

1.  Fork the repository. 
2.  Create a feature branch (`git checkout -b feature/YourAmazingFeature`).
3.  Commit your changes (`git commit -m 'Add YourAmazingFeature'`). 
4.  Push to the branch (`git push origin feature/YourAmazingFeature`).
5.  Open a Pull Request. 

## **License**

Distributed under the MIT License. See `LICENSE.txt` for more information. 

## **Disclaimer**

This toolkit is provided "as-is" for educational and research purposes only. Users are solely responsible for ensuring they have proper authorization before analyzing any files with this tool. The author(s) and contributors are not liable for any misuse or damage caused by this software.
"""
