PeMCP Toolkit - Comprehensive Portable Executable Analysis Suite

The PeMCP Toolkit is a Python-based script designed for in-depth analysis of Portable Executable (PE) files. It provides functionalities for parsing PE structures, enriching data with valuable context, extracting and decoding embedded information, and performing advanced heuristic analysis. The script can be run directly from the command-line for a summary report or as a Model-Context-Protocol (MCP) server for powerful, programmatic integration.

This toolkit moves beyond simple parsing by automating common reverse engineering tasks, such as linking strings to the functions that use them, correlating malware behaviors with suspicious indicators, and ranking strings by their relevance. It is an invaluable tool for malware analysis, reverse engineering, digital forensics, and software auditing.
Prerequisites and Installation

    Python 3.7+: Ensure you have a compatible version of Python installed.

    Clone the Repository:
    Bash

git clone https://github.com/JameZUK/PeMCP/
cd PeMCP

Install Dependencies: The script will automatically prompt you to install missing core or optional dependencies on the first run. Alternatively, you can install them manually. The core dependency is pefile. All other libraries are optional but highly recommended for full functionality.
Bash

    pip install pefile "flare-capa" "flare-floss" "flare-stringsifter" "thefuzz[speedup]" "yara-python" cryptography requests signify "mcp-sdk[cli]"

        Core Libraries:
            pefile: The essential library for parsing the PE file structure.
        Highly Recommended Analysis Libraries:
            flare-floss: Required for advanced string extraction (static, stack, tight, decoded).
            vivisect: A critical dependency for flare-floss and all context-aware analysis (e.g., string-to-function linking).
            flare-capa: Required for identifying program capabilities.
            flare-stringsifter: Required for ranking strings by relevance, a core feature of the toolkit.
            thefuzz[speedup]: Enables powerful fuzzy string searching capabilities.
            yara-python: Required for all YARA scanning functionality.
        Utility and Integration Libraries:
            cryptography: For advanced parsing of digital signature certificate details.
            signify: For validation of Authenticode digital signatures.
            requests: For automatically downloading the PEiD database, Capa rules, and for VirusTotal queries.
            mcp[cli]: Required only for running in --mcp-server mode.

    Data Files:
        PEiD Database (userdb.txt): Handled automatically by the script.
        Capa Rules: Handled automatically by the script.

Docker Usage

For a consistent and isolated environment, you can run the PeMCP toolkit inside a Docker container. This manages all Python dependencies for you. The Dockerfile is included in this repository.
1. Build the Docker Image

From your terminal, in the root directory of this repository (where the Dockerfile is located), run the build command:
Bash

docker build -t pemcp-toolkit .

2. Prepare Local Directories and Run

To analyze files, you need to mount them into the container. It's best practice to create local directories for your samples and rules.
Bash

# Create directories to hold your samples and rules
mkdir -p local_data/malware
mkdir -p local_data/rules/yara

# Place your PE file (e.g., sample.exe) into local_data/malware/
# Place your YARA rules into local_data/rules/yara/

Option A: Run a One-Shot CLI Analysis

This command runs the analysis, prints the report to your console, and then the container is removed.
Bash

docker run --rm \
  -v "$(pwd)/local_data/malware:/app/malware" \
  pemcp-toolkit \
  --input-file /app/malware/sample.exe --verbose

Option B: Run as an Interactive MCP Server

This is the recommended way to use the full power of the toolkit. It starts the server, maps the port to your local machine, and mounts your data directories.
Bash

docker run --rm -it \
  -p 127.0.0.1:8082:8082 \
  -v "$(pwd)/local_data/malware:/app/malware" \
  -v "$(pwd)/local_data/rules:/app/rules" \
  pemcp-toolkit \
  --mcp-server \
  --input-file /app/malware/sample.exe \
  --mcp-host 0.0.0.0 \
  --yara-rules /app/rules/yara

Explanation of the docker run command:

    --rm: Automatically removes the container when it exits.
    -it: Runs in interactive mode, showing you the server logs. You can stop it with Ctrl+C. Use -d to run it in the background (detached).
    -p 127.0.0.1:8082:8082: Maps port 8082 from the container to port 8082 on your local machine (localhost).
    -v "$(pwd)/local_data/malware:/app/malware": Mounts your local malware directory to the /app/malware directory inside the container.
    -v "$(pwd)/local_data/rules:/app/rules": Mounts your local rules directory, allowing you to use custom YARA or Capa rules from within the container.
    --mcp-server: The flag to start the server.
    --input-file /app/malware/sample.exe: Crucially, the path to the file is the path inside the container.
    --mcp-host 0.0.0.0: Required for the server inside the container to be accessible from your host machine via the mapped port.
    --yara-rules /app/rules/yara: An example of using the mounted volume to provide custom rules to the script.

Overview of PeMCP Functionality

The PeMCP Toolkit (PeMCP.py) offers two primary modes of operation:

    Command-Line Interface (CLI) Mode:
        Description: Performs a comprehensive static analysis of a specified PE file and prints a detailed report to the console. This mode is best for getting a quick, high-level overview of a file.
        Invocation:
        Bash

    python PeMCP.py --input-file <file_path> [options]

Model-Context-Protocol (MCP) Server Mode:

    Description: The most powerful mode. It runs as an MCP server, pre-analyzing a single PE file at startup and enriching the data with advanced context. All MCP tools then operate on this pre-loaded file's data, allowing for deep, interactive, and programmatic analysis. The server will only become fully available after the initial analysis completes successfully.
    Invocation:
    Bash

        python PeMCP.py --mcp-server --input-file <file_path> [server_options]

Core Analysis Capabilities:

    Detailed PE Structure Parsing: DOS Header, NT Headers, Data Directories, Section Table, etc.
    Hashing: MD5, SHA1, SHA256 for the full file and individual sections. Includes an integrated pure-Python SSDeep for fuzzy hashing.
    Import/Export Analysis: Detailed listing of imported DLLs and functions (including delay-loaded imports) and exported functions.
    Advanced String Analysis:
        FLOSS Extraction: Uses flare-floss for advanced extraction of static, stack, tight, and decoded strings.
        StringSifter Ranking: Automatically ranks all extracted strings by their likely relevance for malware analysis using flare-stringsifter.
        Indicator Categorization: Automatically categorizes strings by type (e.g., url, ipv4, filepath, registry_key).
        Fuzzy Search: Provides a tool to find strings that are similar, but not identical, to a search query using thefuzz.
    Enriched Analysis Context:
        String-to-Function Linking: Automatically finds which functions reference specific static strings.
        Disassembly Snippets: Provides the disassembly context around each string reference, showing how the string is used in code.
        Behavior Correlation: Automatically correlates strings with program capabilities identified by Capa (e.g., links a URL string to the function that Capa flags for network communication).
    Advanced Obfuscation Detection:
        Multi-Layer Decoding: The encoded string finder can now recursively decode multiple layers of encoding (e.g., a Base64 string that decodes to a Hex string).
        Heuristic-Based Confidence: Assigns a confidence score to decoded strings based on their location (e.g., higher confidence for strings in data sections).
        XOR Bruteforcing: Includes a decoder to automatically find the key for and decode single-byte XORed strings.
    Signature & Capability Detection:
        Capa: Identifies program capabilities based on the MITRE ATT&CK framework.
        YARA: Scans the file with user-provided YARA rules.
        PEiD: Matches packer and compiler signatures.
    Other PE Features: Rich Header decoding, Version Information, Digital Signatures, Debug Information (PDB paths), TLS Callbacks, Load Configuration, and more.

CLI Mode Command-Line Usage

This mode is best for a quick, static report. For deep, interactive analysis and to access the most advanced features, use the MCP Server Mode.

Full Usage:
Bash

python PeMCP.py --input-file <file_path> [options]

    --input-file <file_path>: (Required) Path to the PE file to analyze.
    -v, --verbose: Enable more detailed output.
    -d, --db <PATH_TO_USERDB>: Custom path to PEiD userdb.txt.
    -y, --yara-rules <RULES_PATH>: Path to a YARA rule file or directory.
    --capa-rules-dir <PATH>: Directory containing Capa rule files.
    --skip-capa, --skip-floss, etc.: Options to skip specific, time-consuming analyses.

For a complete and current list of all command-line options, run:
Bash

python PeMCP.py --help

MCP Server Mode Operation

When run with --mcp-server, the script becomes a powerful backend for programmatic analysis. The server pre-analyzes the specified input file and exposes a rich API for querying the results.
Available MCP Tools (Highlights)

The server provides a comprehensive set of tools. Below are some of the most powerful and recently added ones.
Core Analysis & Triage

    get_triage_report: (New) Runs an automated workflow to find the most suspicious indicators (high-score strings, suspicious imports, high-severity capabilities) and returns a condensed summary report. Ideal for initial triage.
    reanalyze_loaded_pe_file: Re-triggers the full analysis pipeline on the loaded file, with options to skip certain modules.
    get_analyzed_file_summary: Provides a high-level overview of the PE file's characteristics.

Advanced String Analysis & Searching

    get_top_sifted_strings: Returns a list of the most relevant strings, sorted by their sifter_score. Now includes powerful granular filters for score, length, category, and regex.
    fuzzy_search_strings: (New) Performs a fuzzy search to find strings that are similar to a given query. Excellent for finding obfuscated or slightly misspelled strings.
    find_and_decode_encoded_strings: Finds and decodes potentially encoded substrings. Now features multi-layer decoding and a confidence score based on heuristics.
    search_floss_strings: Performs a regex search across all strings extracted by FLOSS.

Context & Correlation Tools

    get_string_usage_context: (New) For a given static string's file offset, this tool returns the disassembly snippets for every location in the code where the string is used.
    get_strings_for_function: (New) For a given function's address, this tool returns all strings that are referenced by that function.

PE Structure & Utilities

    Detailed Information Tools: A full suite of tools like get_imports_info, get_sections_info, get_capa_analysis_info, etc., provide complete access to every part of the parsed PE file.
    Deobfuscation & Dumping: Tools like deobfuscate_base64, deobfuscate_xor_single_byte, and get_hex_dump provide low-level data manipulation capabilities.
    External Integration: The get_virustotal_report_for_loaded_file tool can query the VirusTotal API for reputation information on the loaded file.

How It Works (General Principles)

    PE Analysis: Primarily uses the pefile library for parsing PE structures. Hashes are calculated using hashlib and the integrated SSDeep class.
    External Tool Integration: Leverages yara-python, flare-capa, flare-floss, flare-stringsifter, and thefuzz through their Python APIs.
    Contextual Analysis: Uses the vivisect workspace (provided by flare-floss) to perform advanced code analysis, such as finding cross-references between code and data.
    MCP Server: Uses the modelcontextprotocol library to expose its analysis tools.

Limitations

    Static Analysis Only: The script performs static analysis and does not execute the PE files. Dynamic behavior is not observed.
    Advanced Obfuscation: While the toolkit has features to combat common encoding and obfuscation, its effectiveness against sophisticated, custom packers or runtime-only string construction is limited by the underlying static analysis engines.
    Authenticode Full Chain Validation: Relies on signify; comprehensive trust chain validation might depend on system certificate stores.

Contributing

Contributions are welcome! Please follow standard GitHub practices:

    Fork the repository.
    Create a feature branch (git checkout -b feature/YourAmazingFeature).
    Commit your changes (git commit -m 'Add YourAmazingFeature').
    Push to the branch (git push origin feature/YourAmazingFeature).
    Open a Pull Request.

License

Distributed under the MIT License. See LICENSE.txt for more information.
Disclaimer

This toolkit is provided "as-is" for educational and research purposes only. Users are solely responsible for ensuring they have proper authorization before analyzing any files with this tool. The author(s) and contributors are not liable for any misuse or damage caused by this software.
