# PeMCP Toolkit - Comprehensive Portable Executable Analysis Suite

The PeMCP Toolkit is a suite of Python-based command-line utilities designed for in-depth analysis of Portable Executable (PE) files and related binary data. It provides tools for parsing PE structures, examining raw file content, extracting embedded information, and performing advanced heuristic analysis. This toolkit is invaluable for malware analysis, reverse engineering, digital forensics, and software auditing.

## Overview of PeMCP Toolkit Utilities

The PeMCP Toolkit offers a range of functionalities, likely accessed through the main `PeMCP.py` script via subcommands or specific flags. These core utilities include:

1.  **Full PE Analysis (`analyze` or default command):**
    * **Description:** The primary utility for comprehensive static analysis of PE file structures. It extracts detailed metadata from all parts of the PE header, sections, data directories, imports/exports, resources, and more.
    * **Key Outputs:** PE type, architecture, timestamps, hashes (MD5, SHA1, SHA256), section details (entropy, hashes), import/export tables, resource lists, Rich Header info, PEiD signatures, ImpHash, version information, Authenticode signature presence.

2.  **Hex Dump Utility (`hexdump` command):**
    * **Description:** Provides a classical hexadecimal and ASCII representation of the raw byte content of any given file or a specific region within it. Essential for low-level binary examination.
    * **Key Features:** Displays file offsets, customizable start offset, length of dump, and bytes per line.

3.  **String Extraction Utility (`strings` command):**
    * **Description:** Scans a file for sequences of printable ASCII and Unicode (UTF-16LE) characters. Useful for discovering embedded paths, URLs, commands, configuration data, or suspicious messages.
    * **Key Features:** Configurable minimum string length, filtering for ASCII/Unicode, display of string offsets.

4.  **SSDeep Fuzzy Hashing (integrated into PE Analysis):**
    * **Description:** Calculates the context-triggered piecewise hash (fuzzy hash) of the file. This is used to identify similar but not identical files, which is particularly useful for tracking malware variants.
    * **Invocation:** Typically part of the default full PE analysis output. May have a flag like `--ssdeep-only` for focused calculation.

5.  **Capa Capability Analysis (potential integration, possibly via `--capa` flag):**
    * **Description:** *(Assumed Feature)* Integrates with the Capa tool to identify the capabilities of an executable (e.g., "encrypts data," "creates network connections," "queries registry"). It can map these capabilities to known malware behaviors and ATT&CK techniques.
    * **Invocation:** Likely enabled with a specific flag (e.g., `--enable-capa` or `--capa`) during a PE analysis run.

*(This section provides a high-level overview. Detailed features and command-line options for each utility are described in subsequent sections or can be found by running the script with the `--help` flag for each specific command/utility.)*

---

## 1. PeMCP Analyzer (Core PE Parsing Functionality)

This is the flagship tool for deep dives into PE file structures, typically invoked by default or with an `analyze` subcommand.

### PeMCP Analyzer Features:

* **Basic File Information:**
    * File Path, File Size
    * Standard Hashes: MD5, SHA1, SHA256
    * **SSDeep (Fuzzy Hash):** Generates context-triggered piecewise hashes for similarity comparisons.
* **PE Type Identification:**
    * Validates PE format (EXE, DLL, SYS).
    * Detects architecture: 32-bit (PE32) or 64-bit (PE32+).
* **Detailed PE Header Parsing:**
    * DOS, NT, File (COFF), and Optional Headers.
    * Includes fields like Entry Point, Image Base, Subsystem, Checksum, Linker Version, etc.
* **Data Directories Analysis:** Comprehensive parsing of all standard data directories (Export, Import, Resource, Exception, Certificate, Relocations, Debug, TLS, Load Config, IAT, etc.).
* **Section Analysis:** For each section:
    * Name, Virtual Address/Size, Raw Data Pointer/Size, Characteristics.
    * **Entropy Calculation:** To identify potentially packed or encrypted data.
    * **Section Hashes:** MD5, SHA1, SHA256 of individual section content.
* **Import/Export Analysis:**
    * Lists imported DLLs and functions (by name/ordinal).
    * Lists exported functions (name, ordinal, address).
* **Resource Parsing:** Enumerates resources by Type, Name/ID, Language; provides offset and size.
* **TLS, Debug, and Load Configuration Details.**
* **Rich Header Decoding:** Parses and decodes the "Rich" header, revealing build environment details.
* **PEiD Signatures:** Matches packer/compiler signatures using an external `userdb.txt`.
* **ImpHash (Import Hash):** Calculates the ImpHash for malware clustering.
* **Authenticode Signature Check:** Basic verification of digital signature presence.
* **Version Information:** Extracts string-based version info (ProductName, FileVersion, etc.).
* **Capa Analysis (Potential Integration):**
    * *(Assumed Feature)* May integrate with `capa` to identify program capabilities and map to ATT&CK techniques.

### PeMCP Analyzer Command-Line Usage (Illustrative):

    python PeMCP.py [analyze] [options] <file_path_or_directory>
    # 'analyze' might be the default command if no other utility is specified

* **`<file_path_or_directory>`**: (Required) Path to the PE file or a directory.
* **`-o FILE, --output FILE`**: Write analysis output to a specified file.
* **`-j, --json`**: Output results in JSON format.
* **`-v, --verbose`**: Enable more detailed output.
* **`--no-hashes, --no-ssdeep, --no-sections, ...`**: Flags to disable specific parts of the analysis.
* **`--userdb PATH`**: Custom path to `userdb.txt`.
* **`--enable-capa, --capa-path PATH`**: Options for Capa integration (if available).
* **`-R, --recursive`**: Process directory recursively.
* See `python PeMCP.py --help` or `python PeMCP.py analyze --help` for a full list.

---

## 2. Hex Dump Utility

This utility provides a classic hexadecimal and ASCII view of a file's content.

### Hex Dump Features:

* Displays file content in a side-by-side hexadecimal and printable ASCII representation.
* Shows file offsets for easy navigation.
* Option to specify start offset and length of the dump.
* Customizable line width (bytes per line).

### Hex Dump Command-Line Usage (Illustrative):

    python PeMCP.py hexdump [options] <file_path>

**Common Options:**

* **`<file_path>`**: (Required) Path to the file to dump.
* **`-s OFFSET, --start-offset OFFSET`**: Start dumping from this byte offset (hex `0x...` or decimal).
* **`-l LENGTH, --length LENGTH`**: Dump only this many bytes (hex `0x...` or decimal).
* **`-w WIDTH, --width WIDTH`**: Number of bytes per line (default: 16).
* **`--no-ascii`**: Suppress the ASCII representation.
* See `python PeMCP.py hexdump --help` for a full list.

**Example:**

    python PeMCP.py hexdump malware.exe --start-offset 0x1000 --length 256

---

## 3. String Extraction Utility

This utility extracts sequences of printable characters (strings) from binary files.

### String Extraction Features:

* Extracts both ASCII (7-bit) and Unicode (UTF-16LE) strings.
* Option to specify minimum string length.
* Displays the file offset where each string is found.
* Filtering options (ASCII/Unicode).

### String Extraction Command-Line Usage (Illustrative):

    python PeMCP.py strings [options] <file_path>

**Common Options:**

* **`<file_path>`**: (Required) Path to the file.
* **`-n LENGTH, --min-length LENGTH`**: Minimum length of strings (default: 4 or 5).
* **`-a, --ascii-only`**: Extract only ASCII strings.
* **`-u, --unicode-only`**: Extract only Unicode strings.
* **`-o, --show-offset`**: Print the offset of each string.
* **`-t FORMAT, --offset-format FORMAT`**: Offset format (`d` for decimal, `x` for hex; default: `x`).
* See `python PeMCP.py strings --help` for a full list.

**Example:**

    python PeMCP.py strings config.sys --min-length 8 --unicode-only

---

## General Toolkit Information

### Requirements

* **Python 3.x**
* **pefile:** Core library for PE parsing.
* **python-ssdeep:** For fuzzy hashing.
* **(Optional) userdb.txt:** For PEiD signatures.
* **(Potentially) Capa:** If Capa analysis is integrated.

### Installation

1.  **Clone the repository or download script(s):**
    ```
    git clone [https://github.com/JameZUK/PeMCP.git](https://github.com/JameZUK/PeMCP.git)
    cd PeMCP
    ```
2.  **Install Python dependencies:**
    ```
    pip install pefile python-ssdeep
    ```
    *(Install other dependencies like `capa` if needed).*
3.  **(Optional) Obtain `userdb.txt`:** Place in the script's directory or as configured.

### Overall Command-Line Philosophy

The PeMCP toolkit likely uses a main script (`PeMCP.py`) with subcommands (e.g., `analyze`, `hexdump`, `strings`) to invoke different utilities. Each subcommand will have its own specific options.

    python PeMCP.py --help  # General help for the toolkit
    python PeMCP.py analyze --help # Help for PE analysis
    python PeMCP.py hexdump --help # Help for hex dump utility
    python PeMCP.py strings --help # Help for string extraction

### How It Works (General Principles)

* **PE Analyzer:** Uses `pefile` for PE structures, `hashlib`/`python-ssdeep` for hashes, `math` for entropy. Custom logic for Rich Header, PEiD, ImpHash. Capa integration likely via subprocess or API.
* **Hex Dump Utility:** Reads file in binary, formats bytes to hex/ASCII.
* **String Search Utility:** Scans for printable ASCII/UTF-16LE sequences.

### Limitations

* **Static Analysis Only:** Does not execute files.
* **Advanced Obfuscation:** May struggle with heavily obfuscated files.
* **Packed/Encrypted Files:** Analysis is on the outer layer unless manually unpacked.
* **Authenticode Full Validation:** Basic check; full validation needs dedicated tools.

### Contributing

Contributions are welcome!
1.  Fork the repository.
2.  Create a feature branch.
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

### License

Refer to the `LICENSE` file. If absent, contact the author or assume a standard open-source license.

### Disclaimer

For educational/research purposes. Use responsibly with proper permissions. Author(s) not liable for misuse.
