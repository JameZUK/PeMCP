# PeMCP - Portable Executable Metadata Collection and Parsing Tool

PeMCP is an advanced Python script designed for in-depth analysis of Portable Executable (PE) files. It meticulously parses PE structures to extract a comprehensive set of metadata, aiding in malware analysis, reverse engineering, digital forensics, and software auditing. The tool aims to provide a detailed understanding of Windows executables (EXE), dynamic-link libraries (DLL), and system drivers (SYS).

## Features

PeMCP offers a rich set of features for PE file examination:

* **Basic File Information:**
    * File Path, File Size
    * Standard Hashes: MD5, SHA1, SHA256
    * **SSDeep (Fuzzy Hash):** Generates a context-triggered piecewise hash, useful for identifying similar but not identical files.
* **PE Type Identification:**
    * Confirms if the file is a valid PE.
    * Identifies type: EXE, DLL, or SYS.
    * Detects architecture: 32-bit (PE32) or 64-bit (PE32+).
* **Detailed PE Header Parsing:**
    * **DOS Header:** `e_magic` (MZ signature), `e_lfanew` (offset to NT headers).
    * **NT Headers:** Signature (PE\0\0).
    * **File Header (COFF):** Machine type, Number of Sections, Compilation Timestamp, Pointer/Number of Symbols, Size of Optional Header, Characteristics (e.g., executable, DLL).
    * **Optional Header:**
        * Magic (PE32/PE32+), Linker Version, Size of Code/Data sections.
        * Address of Entry Point, Base of Code/Data.
        * Image Base, Section/File Alignment.
        * OS/Image/Subsystem Versions.
        * Size of Image/Headers, PE Checksum.
        * Subsystem (GUI, Console, Native), DLL Characteristics.
        * Stack/Heap Reserve/Commit sizes.
        * Number of RVA and Sizes (Data Directories count).
* **Data Directories Analysis:** Detailed parsing of all standard data directories, including:
    * Export Table (EAT)
    * Import Table (IAT)
    * Resource Table
    * Exception Table
    * Certificate Table (Authenticode Signature Location)
    * Base Relocation Table
    * Debug Directory
    * Architecture Specific Data
    * Global Pointer
    * TLS (Thread Local Storage) Table
    * Load Config Table
    * Bound Import Table
    * Import Address Table (IAT)
    * Delay Import Descriptor
    * CLR Runtime Header (for .NET assemblies)
* **Section Analysis:** For each section:
    * Name (e.g., .text, .data, .rsrc)
    * Virtual Address, Virtual Size
    * Raw Data Size, Pointer to Raw Data
    * Characteristics (readable, writable, executable, etc.)
    * **Entropy Calculation:** Helps identify packed or encrypted sections.
    * **Section Hashes:** MD5, SHA1, SHA256 of individual section data.
* **Import/Export Analysis:**
    * **Imports:** Lists all imported DLLs and the functions/ordinals imported from each.
    * **Exports:** Lists all functions/ordinals exported by the PE file, including names, ordinals, and addresses.
* **Resource Parsing:**
    * Enumerates resources by Type, Name/ID, Language, and Sublanguage.
    * Provides offset and size for each resource.
* **TLS (Thread Local Storage) Details:**
    * Start/End Addresses of Raw Data, Address of Index, Address of Callbacks.
* **Debug Information:**
    * Type (e.g., CodeView, POGO), Timestamp, Format.
    * PDB File Name and GUID (if available from CodeView debug info).
* **Load Configuration Structure:**
    * Detailed parsing of security-related fields like Security Cookie (GS), SEH Handler, Guard CF flags, Code Integrity information, etc.
* **Rich Header Decoding:**
    * Parses and decodes the "Rich" header (if present) to reveal information about the build environment (e.g., Microsoft Visual Studio versions).
    * Verifies Rich Header checksum.
* **PEiD Signatures:**
    * Matches packer, cryptor, and compiler signatures using an external `userdb.txt` database (if provided and integrated).
* **ImpHash (Import Hash):**
    * Calculates the ImpHash, useful for clustering malware samples.
* **Authenticode Signature Check:**
    * Basic check for the presence and validity of an Authenticode digital signature. *(Note: For full chain validation, external tools are recommended).*
* **Version Information:**
    * Extracts string-based version information from resources (e.g., FileDescription, ProductName, OriginalFilename, FileVersion, ProductVersion, CompanyName, LegalCopyright).
* **Capa Analysis (Potential Feature):**
    * *(Assumption: If integrated, PeMCP might execute Capa against the target file and incorporate its findings.)*
    * Identifies capabilities of the program (e.g., "creates mutex", "encrypts data", "contains HTTP client").
    * May list ATT&CK techniques and other relevant metadata provided by Capa.

## "MCP" Tools Philosophy

The "MCP" in PeMCP likely stands for "Metadata Collection and Parsing." The script itself is the primary tool, designed to be a comprehensive, standalone utility for PE file analysis. It doesn't necessarily imply a suite of separate external "MCP tools" but rather a focused approach on extracting and presenting as much metadata as possible from the PE file format.

## Requirements

* **Python 3.x**
* **pefile:** Core library for PE parsing.
* **ssdeep (python-ssdeep):** For fuzzy hashing. (Likely dependency)
* **(Optional) userdb.txt:** For PEiD signature matching. This file (often from the PEiD tool) should be in the script's directory or a configurable path.
* **(Potentially) Capa:** If Capa analysis is integrated, the Capa executable would need to be installed and in the system's PATH, or its path provided to the script. Relevant Capa Python libraries might also be dependencies.

## Installation

1.  **Clone the repository or download `PeMCP.py`:**
    ```
    git clone [https://github.com/JameZUK/PeMCP.git](https://github.com/JameZUK/PeMCP.git)
    cd PeMCP
    ```
2.  **Install dependencies:**
    ```
    pip install pefile python-ssdeep 
    ```
    *(Note: Additional dependencies might be required if Capa or other specific features are used).*
3.  **(Optional) Obtain `userdb.txt`:** Place it in the script's directory for PEiD functionality.
4.  **(Potentially) Install Capa:** If using Capa features, download Capa from its official repository and ensure it's accessible.

## Command-Line Arguments

*(The following is a speculative list based on common practices for such tools. The actual arguments might differ. Refer to `python PeMCP.py --help` for definitive options.)*

PeMCP is typically run from the command line:

    python PeMCP.py [options] <file_path_or_directory>

**Possible Options:**

* **`file_path_or_directory`**: (Required) Path to the PE file or a directory containing PE files to analyze.
* **`-h, --help`**: Show help message and exit.
* **`-o FILE, --output FILE`**: Write output to a specified file instead of stdout.
* **`-j, --json`**: Output results in JSON format. Useful for machine parsing.
* **`-v, --verbose`**: Enable verbose output, showing more detailed parsing steps or debug information.
* **`--no-hashes`**: Disable calculation of standard file hashes (MD5, SHA1, SHA256).
* **`--no-ssdeep`**: Disable calculation of ssdeep fuzzy hash.
* **`--no-sections`**: Disable detailed section analysis.
* **`--no-imports`**: Disable import table analysis.
* **`--no-exports`**: Disable export table analysis.
* **`--no-resources`**: Disable resource parsing.
* **`--no-richheader`**: Disable Rich header parsing.
* **`--no-peid`**: Disable PEiD signature scanning.
* **`--userdb PATH`**: Specify a custom path to `userdb.txt` for PEiD signatures.
* **`--enable-capa`**: Enable Capa analysis (if integrated).
* **`--capa-path PATH`**: Specify the path to the Capa executable (if not in PATH and Capa analysis is enabled).
* **`--capa-rules PATH`**: Specify custom Capa rules directory/files.
* **`-R, --recursive`**: If a directory is provided as input, process files recursively.

**Example Usage:**

    # Analyze a single PE file and print to console
    python PeMCP.py C:\Windows\System32\notepad.exe

    # Analyze a file and save output to a JSON file
    python PeMCP.py malware.exe -o analysis_results.json --json

    # Analyze all PE files in a directory recursively, with verbose output
    python PeMCP.py /samples/malware_collection/ -R -v

    # Analyze a file with Capa integration (hypothetical)
    python PeMCP.py suspicious.dll --enable-capa --capa-path /usr/local/bin/capa

## Output Structure

The script outputs a structured report, typically organized by PE file components. If JSON output is selected, it will be a structured JSON object.

(Example console output structure remains similar to the previous version, but would include ssdeep and potentially Capa results.)

    ...
    [+] Basic File Information
        ...
        SSDeep: ...

    ...
    [+] Capa Analysis (if enabled and results found)
        [>] Capabilities:
            - encrypts data (ATT&CK T1486)
            - creates mutex
        [>] Matched Rules:
            - rule_name_1
            - rule_name_2
    ...

## How it Works

* **Core Parsing (`pefile`):** PeMCP heavily relies on the `pefile` library to navigate and interpret the PE file structure.
* **Hashing (`hashlib`, `ssdeep`):** Standard hashes are computed using `hashlib`. Fuzzy hashing (ssdeep) is likely implemented using the `python-ssdeep` library.
* **Entropy (`math`):** Shannon entropy is calculated for sections to detect potential packing or encryption.
* **PEiD Signatures:** If `userdb.txt` is present and this feature is enabled, the script likely scans the entry point or other parts of the file against known signatures.
* **ImpHash:** Calculated by normalizing and hashing imported function names and their DLLs.
* **Rich Header:** Involves locating the Rich header marker, decoding its XORed data, and parsing the product entries.
* **Capa Integration (Speculative):** If Capa is integrated, PeMCP would likely:
    1.  Execute the `capa` command-line tool as a subprocess, passing the target file.
    2.  Capture Capa's output (often JSON).
    3.  Parse this output to extract identified capabilities, ATT&CK mappings, and rule matches.
    4.  Incorporate this information into its own report.
    Alternatively, it might use a direct Python binding or library for Capa if available.

## Limitations

* **Dynamic Analysis:** PeMCP performs static analysis. It does not execute the file, so runtime behaviors are not observed.
* **Advanced Obfuscation/Anti-Analysis:** Heavily obfuscated files or those employing sophisticated anti-disassembly or anti-parsing techniques might not be fully or accurately parsed.
* **Packed/Encrypted Files:** While features like entropy and PEiD can suggest packing, PeMCP does not inherently unpack or decrypt files. Analysis will be on the packer stub unless the file is manually unpacked first.
* **Authenticode Full Validation:** The signature check is primarily for presence and basic structure. Full cryptographic validation requires dedicated tools.
* **Capa Dependency:** If Capa analysis is included, its accuracy depends on the Capa tool itself and its ruleset.

## Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes:
1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/YourFeature`).
6.  Open a Pull Request.

## License

Refer to the `LICENSE` file in the repository. If not present, assume it's a standard open-source license (e.g., MIT, Apache 2.0) or contact the author.

## Disclaimer

This tool is for educational and research purposes. Analyze only files you have explicit permission to examine. The author(s) are not responsible for misuse.
