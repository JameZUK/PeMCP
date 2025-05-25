# **PeMCP Toolkit \- Comprehensive Portable Executable Analysis Suite**

The PeMCP Toolkit is a Python-based script designed for in-depth analysis of Portable Executable (PE) files. It provides functionalities for parsing PE structures, examining raw file content, extracting embedded information, and performing advanced heuristic analysis. The script can be run directly from the command-line for interactive analysis or as a Model-Context-Protocol (MCP) server for programmatic integration. This toolkit is invaluable for malware analysis, reverse engineering, digital forensics, and software auditing.

## **Overview of PeMCP Functionality**

The PeMCP Toolkit (PeMCP.py) offers two primary modes of operation:

1. **Command-Line** Interface **(CLI) Mode:**  
   * **Description:** Performs a comprehensive static analysis of a specified PE file and prints a detailed report to the console. Includes options for PEiD-like signature scanning, YARA scanning, Capa capability detection, string extraction/searching, and hex dumping of file content based on command-line flags.  
   * **Invocation:**  
     python PeMCP.py \--input-file \<file\_path\> \[options\]

2. **Model-Context-Protocol (MCP) Server Mode:**  
   * **Description:** Runs as an MCP server, pre-analyzing a single PE file specified by \--input-file at startup. All MCP tools then operate on this pre-loaded file's data. The server will only become fully available after the initial analysis (including potentially long-running components like Capa) completes successfully. A tool is provided to re-trigger analysis on this pre-loaded file.  
   * **Invocation:**  
     python PeMCP.py \--mcp-server \--input-file \<file\_path\> \[server\_options\]

### **Core Analysis Capabilities:**

Regardless of the mode, PeMCP leverages pefile for deep PE structure parsing and integrates several analysis techniques:

* Detailed PE Structure Parsing: DOS Header, NT Headers (File Header, Optional Header), Data Directories, Section Table.  
* Hashing: MD5, SHA1, SHA256 for the full file and individual sections. Includes an integrated pure-Python **SSDeep** for fuzzy hashing.  
* Import/Export Analysis: Detailed listing of imported DLLs and functions (including delay-loaded imports) and exported functions.  
* Resource Analysis: Summary of embedded resources.  
* Signature-Based Detection:  
  * **PEiD Signatures:** Matches packer/compiler signatures using a userdb.txt (downloaded automatically if requests is installed and the file is not found).  
  * **YARA Scanning:** If yara-python is installed and rule files are provided.  
* Capability Analysis:  
  * **Capa:** If flare-capa is installed and rule/signature files are available, identifies program capabilities. The script can manage automatic download of Capa rules.  
* Other PE Features: Rich Header decoding, Version Information, Debug Information (PDB paths), TLS Callbacks, Load Configuration, COM Descriptor (for .NET), Overlay data, Base Relocations, Bound Imports, Exception Data, COFF Symbols, and Checksum Verification.  
* String & Hex Utilities (CLI Mode): Options to extract strings, search for specific strings, and perform hex dumps are available as command-line flags in CLI mode.  
* MCP Tools (Server Mode): A comprehensive set of tools to access parsed data, re-trigger analyses on the pre-loaded file, and perform utility functions (see MCP Server Mode section for details).

## **1\. CLI Mode Operation**

This is the primary mode for direct, command-line based analysis of a single PE file.

### **Key Analysis Sections in CLI Output:**

* File Hashes (MD5, SHA1, SHA256, SSDeep)  
* DOS Header details  
* NT Headers (File Header, Optional Header) details, including PE type (32/64-bit) and characteristics  
* Data Directories (listing RVA and Size for each)  
* Section Table (Name, Virtual Address/Size, Raw Data Pointer/Size, Characteristics, Entropy, Hashes of section data)  
* Import Table (DLLs and their imported functions/ordinals)  
* Export Table (Exported function names, ordinals, addresses, forwarders)  
* Resource Directory Summary  
* Version Information (from version resources)  
* Debug Information (including PDB path if present)  
* Digital Signatures (Authenticode, with certificate details via cryptography and validation via signify)  
* PEiD Signature Matches  
* YARA Scan Results (if rules provided)  
* Capa Capability Analysis (if rules/signatures provided)  
* Rich Header information  
* Delay-Load Imports, TLS Information, Load Configuration, COM Descriptor, Overlay Data, Base Relocations, Bound Imports, Exception Data, COFF Symbol Table, Checksum Verification.  
* PEFile Warnings

### **CLI Mode Command-Line Usage:**

python PeMCP.py \--input-file \<file\_path\> \[options\]

* **\--input-file \<file\_path\>**: (Required) Path to the PE file to analyze.  
* **\-v, \--verbose**: Enable more detailed output, including verbose Capa matches and section data samples.  
* **\-d PATH\_TO\_USERDB, \--db PATH\_TO\_USERDB**: Custom path to PEiD userdb.txt. Defaults to a script-relative userdb.txt. The script will attempt to download it if not found.  
* **\-y RULES\_PATH, \--yara-rules RULES\_PATH**: Path to a YARA rule file or a directory containing YARA rules.  
* **\--capa-rules-dir PATH\_TO\_CAPA\_RULES**: Directory containing Capa rule files. If not specified or invalid, the script attempts to download them to a default location (./capa\_rules\_store/rules/).  
* **\--capa-sigs-dir PATH\_TO\_CAPA\_SIGS**: Directory for Capa library identification signature files (\*.sig). Optional.  
* **\--skip-capa**: Skip Capa capability analysis entirely.  
* **\--skip-full-peid-scan**: Limits PEiD scan to the entry point only.  
* **\--psah, \--peid-scan-all-sigs-heuristically**: Uses all PEiD signatures (including ep\_only=true ones) for heuristic scanning across sections.

#### **Additional CLI Functionalities (Flags for PeMCP.py):**

* **String Extraction:**  
  * \--extract-strings: Enables string extraction from the entire file.  
  * \--min-str-len LENGTH: Sets the minimum length for extracted strings (default: 5).  
  * \--strings-limit COUNT: Maximum number of strings to display for extraction and per search term (default: 100).  
* **Specific String Search:**  
  * \--search-string "TEXT\_TO\_FIND": Search for one or more specific ASCII strings. Use the flag multiple times for multiple strings.  
* **Hex Dump:**  
  * \--hexdump-offset OFFSET: Hexadecimal (e.g., 0x1000) or decimal offset to start the dump. Requires \--hexdump-length.  
  * \--hexdump-length LENGTH: Number of bytes to dump. Requires \--hexdump-offset.  
  * \--hexdump-lines COUNT: Maximum number of lines for the hex dump output (default: 16).

*For a complete list of current command-line options, run:*  
python PeMCP.py \--help

## **2\. MCP Server Mode Operation**

When run with the \--mcp-server flag, PeMCP.py starts an MCP server that pre-analyzes the file specified by \--input-file. All tools then operate on this pre-loaded file.

### **MCP Server Key Characteristics:**

* **Single File Focus:** The server pre-analyzes one PE file specified by \--input-file at startup. All subsequent tool calls operate on this single pre-loaded file's data.  
* **Startup Analysis:** A full analysis (including PEiD, YARA, and Capa, based on available dependencies and provided rule/signature paths) is performed on the \--input-file *before* the MCP server starts accepting connections. If this initial analysis fails, the script will log an error and exit.  
* **Transport Protocols:** Supports stdio and sse (Server-Sent Events) for communication.  
* **Response Size Limit:** MCP tools enforce a maximum response size (default 64KB) to prevent excessively large data transfers. Tools that retrieve collections or large data segments typically have limit parameters to manage this.

### **MCP Server Command-Line Usage:**

python PeMCP.py \--mcp-server \--input-file \<path\_to\_pe\_file\> \[server\_options\] \[analysis\_dependency\_paths\]

* **\--mcp-server**: Activates MCP server mode.  
* **\--input-file \<path\_to\_pe\_file\>**: (Required in MCP mode) Path to the PE file to be pre-analyzed and served.  
* **\--mcp-host HOST**: Host for SSE server (default: 127.0.0.1).  
* **\--mcp-port PORT**: Port for SSE server (default: 8082).  
* **\--mcp-transport TRANSPORT**: stdio or sse (default: stdio).  
* Other options like \--db, \--yara-rules, \--capa-rules-dir, \--capa-sigs-dir, \--verbose, \--skip-capa, etc., are used for the initial analysis and can be overridden by the reanalyze\_loaded\_pe\_file tool.

### **Core MCP Tools:**

*(Note:* Many tools returning collections or large data have mandatory limit parameters to control response size. These limits must *be positive integers.)*

* **reanalyze\_loaded\_pe\_file**:  
  * **Description:** Re-triggers a full or partial analysis of the PE file pre-loaded at server startup. Updates the global analysis results.  
  * **Arguments:** peid\_db\_path\_override (Optional str), yara\_rules\_path\_override (Optional str), capa\_rules\_dir\_override (Optional str), capa\_sigs\_dir\_override (Optional str), analyses\_to\_skip\_list (Optional List\[str\], e.g., \["peid", "yara"\]), skip\_capa\_analysis\_flag (Optional bool), mcp\_reanalysis\_verbose\_log (bool), peid\_skip\_full\_scan\_flag (bool), peid\_use\_all\_sigs\_heuristically\_flag (bool).  
* **get\_analyzed\_file\_summary**:  
  * **Description:** Retrieves a high-level summary of the pre-loaded and analyzed PE file.  
  * **Argument:** limit\_top\_level\_keys (int, Mandatory).  
* **get\_full\_analysis\_results**:  
  * **Description:** Retrieves the complete analysis results dictionary for the pre-loaded PE file, limited by the number of top-level keys.  
  * **Argument:** limit\_top\_level\_keys (int, Mandatory).  
* **get\_\<key\>\_info Tools (e.g., get\_sections\_info, get\_imports\_info, get\_yara\_scan\_analysis\_info):**  
  * **Description:** Dynamically generated tools to retrieve specific top-level parts of the analysis data (e.g., 'dos\_header\_info', 'sections\_info', 'yara\_scan\_analysis'). The actual data structure returned depends on the key.  
  * **Arguments:** limit\_items (int, Mandatory), offset\_items (Optional int, default 0 for list-based data).  
* **get\_capa\_analysis\_overview**:  
  * **Description:** Retrieves an overview of Capa capability rules from the pre-loaded analysis, with filtering and pagination. For each rule, 'matches' are summarized by a count of unique addresses.  
  * **Arguments:** limit\_rules\_on\_page (int, Mandatory), offset\_rules (Optional int), filter\_by\_rule\_name\_substring (Optional str), filter\_by\_namespace\_exact (Optional str), filter\_by\_attck\_id\_substring (Optional str), filter\_by\_mbc\_id\_substring (Optional str), retrieve\_report\_metadata\_only (bool), source\_text\_truncate\_length (Optional int).  
* **get\_capa\_rule\_match\_details**:  
  * **Description:** Retrieves detailed match information for a single, specified Capa rule, with pagination for match addresses and content control for feature details.  
  * **Arguments:** rule\_id\_to\_fetch (str, Mandatory), limit\_match\_addresses\_on\_page (int, Mandatory), offset\_match\_addresses (Optional int), limit\_feature\_details\_per\_address (Optional int), feature\_value\_text\_truncate\_length (Optional int).  
* **extract\_strings\_from\_loaded\_binary**:  
  * **Description:** Extracts printable ASCII strings from the pre-loaded PE file's binary data.  
  * **Arguments:** limit\_strings\_returned (int, Mandatory), min\_string\_length (int, default 5).  
* **search\_for\_specific\_strings\_in\_loaded\_binary**:  
  * **Description:** Searches for occurrences of specific ASCII strings within the pre-loaded PE file's binary data. Case-sensitive.  
  * **Arguments:** list\_of\_search\_terms (List\[str\], Mandatory), limit\_occurrences\_per\_term (Optional int, default 100).  
* **get\_hex\_dump\_from\_loaded\_binary**:  
  * **Description:** Retrieves a hex dump of a specified region from the pre-loaded PE file.  
  * **Arguments:** start\_file\_offset (int, Mandatory), length\_of\_dump\_bytes (int, Mandatory), bytes\_to\_show\_per\_line (Optional int, default 16), limit\_output\_lines (Optional int, default 256).  
* **find\_and\_decode\_common\_encoded\_substrings**:  
  * **Description:** Searches the pre-loaded binary for potential Base64, Base32, Hex, or URL encoded substrings. Attempts to decode them, filters by printability, length, and optionally by custom regex patterns applied to the decoded strings.  
  * **Arguments:** limit\_decoded\_results (int, Mandatory), min\_len\_base64\_candidate (int, default 20), min\_len\_base32\_candidate (int, default 24), min\_len\_hex\_candidate (int, default 8), min\_len\_url\_candidate (int, default 10), min\_len\_decoded\_printable\_string (int, default 4), min\_printable\_char\_ratio (float, default 0.8), regex\_patterns\_for\_decoded\_strings (Optional List\[str\]).  
* **Utility Tools:**  
  * get\_current\_server\_datetime: Retrieves current UTC and server local time.  
  * deobfuscate\_base64\_string\_from\_hex: Deobfuscates a hex-encoded string presumed to be Base64.  
  * deobfuscate\_data\_with\_single\_byte\_xor: Deobfuscates hex-encoded data using a single-byte XOR key.  
  * check\_string\_if\_mostly\_printable\_ascii: Checks if a string consists mostly of printable ASCII characters.  
  * get\_virustotal\_report\_for\_loaded\_file: Retrieves a VirusTotal report summary for the loaded file's hash (requires VT\_API\_KEY environment variable and requests library).

## **General Toolkit Information**

### **Requirements**

* **Python 3.7+**  
* **pefile**: Core library for PE parsing. (The script will offer to install this via pip if missing and run in an interactive terminal).  
* **Optional Libraries** (The script checks for these at startup and may prompt for installation if run interactively):  
  * **requests**: For downloading the PEiD database, Capa rules, and for VirusTotal queries.  
  * **cryptography**: For advanced parsing and display of digital signature certificate details.  
  * **signify**: For validation of Authenticode digital signatures.  
  * **yara-python**: Required for YARA scanning functionality.  
  * **flare-capa**: Required for Capa program capability analysis.  
  * **mcp\[cli\]** (Model Context Protocol SDK): Required **only** for running in \--mcp-server mode.  
* **SSDeep Functionality**: Provided by an **integrated pure-Python implementation**; no external ssdeep library or C binary is required.  
* **External Data Files (Optional, but recommended for full functionality):**  
  * **userdb.txt**: PEiD signature database. The script will attempt to download it from https://raw.githubusercontent.com/GerkNL/PEid/master/userdb.txt to the script's directory or a specified path if not found (requires requests).  
  * **Capa Rules**: If flare-capa and requests are installed, and rules are not found at the path specified by \--capa-rules-dir (or the default path ./capa\_rules\_store/rules/), the script will attempt to download them from a specific GitHub tag (e.g., v9.1.0).  
  * **Capa Signatures**: For library function identification by Capa. If you have them, place them in a directory (e.g., ./capa\_sigs) and specify this path using \--capa-sigs-dir.

### **Installation**

1. **Clone the repository or download PeMCP.py:**  
   git clone \[https://github.com/YOUR\_USERNAME/PeMCP/\](https://github.com/YOUR\_USERNAME/PeMCP/) \# Replace with your actual repository URL  
   cd PeMCP

2. Install pefile (critical dependency):  
   If you run the script and pefile is missing in an interactive environment, it will offer to install it. Otherwise, you can install it manually:  
   pip install pefile

3. Install Optional Dependencies (Recommended for full functionality):  
   The script will notify you about missing optional dependencies and may offer to install them. You can also install them manually:  
   pip install requests cryptography signify yara-python flare-capa "mcp\[cli\]"

   *(Note: mcp\[cli\] is only necessary if you intend to use the \--mcp-server mode.)*  
4. **Data Files:**  
   * **PEiD Database (userdb.txt):** Handled automatically by the script if requests is available.  
   * **Capa Rules:** Handled automatically by the script if flare-capa and requests are available.  
   * **Capa Signatures:** Place in a directory and use \--capa-sigs-dir if needed.

### **How It Works (General Principles)**

* **PE Analysis:** Primarily uses the pefile library for parsing PE structures. Hashes are calculated using hashlib and the integrated SSDeep class. Custom logic is implemented for parsing specific structures like the Rich Header.  
* **PEiD Scan:** Employs a custom parser for the userdb.txt format and applies regex-compiled signatures.  
* **YARA/Capa Integration:** Leverages the respective Python libraries (yara-python, flare-capa) through their Python APIs.  
* **String/Hex Utilities (CLI):** Implemented using standard Python file I/O and string manipulation.  
* **MCP Server:** Uses the modelcontextprotocol library to expose its analysis tools.

### **Limitations**

* **Static Analysis Only:** The script performs static analysis and does not execute the PE files.  
* **Advanced Obfuscation/Packing:** Effectiveness on heavily obfuscated files depends on pefile and integrated tools.  
* **Authenticode Full Chain Validation:** Relies on signify; comprehensive trust chain validation might depend on system certificate stores.

### **Contributing**

Contributions are welcome\! Please follow standard GitHub practices:

1. Fork the repository.  
2. Create a feature branch (git checkout \-b feature/YourAmazingFeature).  
3. Commit your changes (git commit \-m 'Add YourAmazingFeature').  
4. Push to the branch (git push origin feature/YourAmazingFeature).  
5. Open a Pull Request.

### **License**

*(Please update this section with your chosen license, e.g., MIT, Apache 2.0, or specify if it's proprietary.)*  
Example: Distributed under the MIT License. See LICENSE.txt for more information.

### **Disclaimer**

This toolkit is provided "as-is" for educational and research purposes only. Users are solely responsible for ensuring they have proper authorization before analyzing any files with this tool. The author(s) and contributors are not liable for any misuse or damage caused by this software.
