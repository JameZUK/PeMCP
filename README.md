# PeMCP - Portable Executable Metadata Collection and Parsing Tool

PeMCP is a Python script designed to parse Portable Executable (PE) files and extract a comprehensive set of metadata. This tool is useful for malware analysis, reverse engineering, and digital forensics to quickly understand the structure and characteristics of Windows executables, DLLs, and drivers.

## Features

PeMCP extracts a wide array of information from PE files, including:

* **Basic File Information:**
    * File Path
    * File Size
    * MD5 Hash
    * SHA1 Hash
    * SHA256 Hash
* **PE Type Identification:**
    * Identifies if the file is a PE file.
    * Determines if it's an EXE, DLL, or SYS (driver) file.
    * Detects 32-bit or 64-bit architecture.
* **PE Header Information:**
    * **DOS Header:**
        * Magic Number (`e_magic`)
    * **NT Headers:**
        * Signature
    * **File Header:**
        * Machine type (e.g., IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64)
        * Number of Sections
        * Compilation Timestamp
        * Pointer to Symbol Table (deprecated)
        * Number of Symbols (deprecated)
        * Size of Optional Header
        * Characteristics (e.g., executable, DLL, etc.)
    * **Optional Header:**
        * Magic (PE32 or PE32+)
        * Linker Version (Major/Minor)
        * Size of Code, Initialized Data, Uninitialized Data
        * Address of Entry Point
        * Base of Code, Base of Data (for PE32)
        * Image Base
        * Section Alignment, File Alignment
        * Operating System Version (Major/Minor)
        * Image Version (Major/Minor)
        * Subsystem Version (Major/Minor)
        * Win32 Version Value (reserved)
        * Size of Image, Size of Headers
        * Checksum
        * Subsystem (e.g., GUI, Console)
        * DLL Characteristics
        * Size of Stack Reserve/Commit, Heap Reserve/Commit
        * Loader Flags (reserved)
        * Number of RVA and Sizes (Data Directories)
* **Data Directories:**
    * Export Table
    * Import Table
    * Resource Table
    * Exception Table
    * Certificate Table
    * Base Relocation Table
    * Debug Directory
    * Architecture Specific Data
    * Global Pointer
    * TLS (Thread Local Storage) Table
    * Load Config Table
    * Bound Import Table
    * IAT (Import Address Table)
    * Delay Import Descriptor
    * CLR Runtime Header
* **Sections:**
    * Name
    * Virtual Address
    * Virtual Size
    * Raw Data Size
    * Pointer to Raw Data
    * Entropy
    * MD5, SHA1, SHA256 Hashes of section data
* **Imports:**
    * DLL Name
    * Imported Functions (Name/Ordinal, Address)
* **Exports:**
    * DLL Name (if applicable from export directory)
    * Exported Functions (Name, Ordinal, Address)
* **Resources:**
    * Type (e.g., RT_ICON, RT_VERSION)
    * Name/ID
    * Language
    * Sublanguage
    * Offset
    * Size
* **TLS (Thread Local Storage):**
    * Start Address of Raw Data
    * End Address of Raw Data
    * Address of Index
    * Address of Callbacks
* **Debug Information:**
    * Type (e.g., CodeView, POGO)
    * Timestamp
    * PDB File Name (if available)
* **Load Configuration:**
    * Various security-related flags and pointers (e.g., Security Cookie, SEH Handler, Guard CF)
* **Rich Header:**
    * Decoded Rich Header information, showing compiler and linker versions.
* **PEiD Signatures:**
    * Matches packer/compiler signatures using an external `userdb.txt` (if provided).
* **ImpHash:**
    * Calculates the Import Hash (Imphash) of the PE file.
* **Authenticode Signature:**
    * Checks for the presence of a digital signature (basic check).
* **Version Information:**
    * Extracts string-based version information (e.g., FileDescription, ProductName, FileVersion).

## Requirements

* **Python 3.x**
* **pefile:** A Python library for parsing and working with PE files.
* **(Optional) userdb.txt:** For PEiD signature matching. This file contains signatures for common packers, cryptors, and compilers. It should be placed in the same directory as the script or an appropriate path needs to be configured within the script if modified.

## Installation

1.  **Clone the repository or download the `PeMCP.py` script:**

    ```
    git clone [https://github.com/JameZUK/PeMCP.git](https://github.com/JameZUK/PeMCP.git)
    cd PeMCP
    ```
    Alternatively, download `PeMCP.py` directly.

2.  **Install the `pefile` library:**

    ```
    pip install pefile
    ```

3.  **(Optional) Obtain `userdb.txt`:**
    If you wish to use the PEiD signature matching feature, you will need a `userdb.txt` file. This file is part of the PEiD toolset. You can often find versions of this file online. Place `userdb.txt` in the same directory as `PeMCP.py`.
    *A common source for `userdb.txt` is the original PEiD application package or various forensic/malware analysis tool repositories.*

## Usage

Run the script from the command line, providing the path to the PE file you want to analyze as an argument.

    python PeMCP.py <path_to_pe_file>

**Example:**

    python PeMCP.py C:\Windows\System32\notepad.exe

    python PeMCP.py /path/to/your/malware_sample.exe

The script will print the extracted metadata to the standard output in a structured format.

### Output Structure

The output is organized into sections for easy readability:

    ==================================================
    PeMCP - Portable Executable Metadata Collection and Parsing
    File: <filename>
    ==================================================

    [+] Basic File Information
        File Path: ...
        File Size: ... Bytes
        MD5: ...
        SHA1: ...
        SHA256: ...

    [+] PE File Checks
        Is PE File: ...
        Is EXE: ...
        Is DLL: ...
        Is Driver: ...
        Bitness: ...

    [+] DOS Header
        Magic: ... (MZ)

    [+] NT Headers
        Signature: ... (PE)

    [+] File Header
        Machine: ...
        Number of Sections: ...
        Timestamp: ... (...)
        Pointer to Symbol Table: ...
        Number of Symbols: ...
        Size of Optional Header: ...
        Characteristics: ...
            Flags: ...

    [+] Optional Header
        Magic: ...
        ... (many other fields) ...
        Data Directories:
            EXPORT Table: RVA=..., Size=...
            ... (other data directories) ...

    [+] Sections
        [>] Section .text
            Virtual Address: ...
            Virtual Size: ...
            ... (other section details) ...
            Entropy: ...
            MD5: ...
            SHA1: ...
            SHA256: ...
        ... (other sections) ...

    [+] Imports
        [>] KERNEL32.dll
            LoadLibraryA (0x...)
            GetProcAddress (0x...)
        ... (other imported DLLs and functions) ...

    [+] Exports (if any)
        Number of Exports: ...
        [>] Exported Function Name (Ordinal: ..., Address: ...)
        ... (other exported functions) ...

    [+] Resources (if any)
        [>] Type: RT_ICON (3), Name/ID: 1, Lang: NEUTRAL (0), SubLang: NEUTRAL (0)
            Offset: ..., Size: ...
        ... (other resources) ...

    [+] TLS (Thread Local Storage) (if present)
        ... (TLS details) ...

    [+] Debug Information (if present)
        ... (Debug details) ...

    [+] Load Configuration (if present)
        ... (Load Config details) ...

    [+] Rich Header Info (if present)
        Decoded Rich Header:
            @comp.id Task: ...
            VS_VERSION_INFO: ...
        Checksum: ... (Matches PE Header Checksum: ...)

    [+] PEiD Signatures (if userdb.txt found and signatures match)
        [!] PEiD Signatures:
            Packer Name v1.0
        ...

    [+] ImpHash
        ImpHash: ...

    [+] Authenticode Signature
        Signature Present: ...
        (Note: This is a basic check. Use dedicated tools for full validation.)

    [+] Version Information (if present)
        CompanyName: ...
        FileDescription: ...
        ... (other version strings) ...

    ==================================================
    Analysis Complete.
    ==================================================

## How it Works

PeMCP utilizes the powerful `pefile` library to parse the intricate structure of PE files. It navigates through various headers (DOS, NT, File, Optional), data directories, and section tables to extract meaningful information.

* **Hashing:** Standard cryptographic hashes (MD5, SHA1, SHA256) are calculated for the entire file and for individual sections using the `hashlib` library.
* **Entropy:** Section entropy is calculated to help identify packed or encrypted data.
* **PEiD Signatures:** If `userdb.txt` is available, the script attempts to match known packer/compiler signatures against the PE file's entry point code and other characteristics.
* **ImpHash:** This hash is calculated based on the names and order of imported functions and the DLLs they come from. It's often used to identify related malware samples.
* **Rich Header Parsing:** The script includes logic to decode the "Rich" header, which can provide information about the build environment (e.g., MSVC compiler versions).

## Limitations

* **Encrypted/Packed Files:** While PeMCP can provide some information about packed or encrypted files (e.g., high entropy sections, PEiD signatures for known packers), it does not unpack or decrypt them. The metadata extracted will be primarily for the packer stub.
* **Obfuscated PE Files:** Heavily obfuscated PE files that tamper with header information might not be parsed correctly or completely.
* **Authenticode Validation:** The check for Authenticode signatures is basic (presence of the certificate data directory). For full signature validation and chain of trust verification, dedicated tools like `sigcheck` (Sysinternals) or other cryptographic libraries should be used.
* **PEiD Database Dependency:** The accuracy and coverage of PEiD signature detection depend entirely on the quality and completeness of the `userdb.txt` file used.

## Contributing

Contributions to PeMCP are welcome! If you have suggestions for improvements, new features, or bug fixes, please feel free to:

1.  Fork the repository.
2.  Create a new branch for your feature or fix.
3.  Make your changes.
4.  Submit a pull request with a clear description of your changes.

## License

This script is likely distributed under an open-source license. Please refer to the `LICENSE` file in the repository (if available) or contact the author for specific licensing information. (Assuming MIT or similar if not specified, but good practice to check).

## Disclaimer

This tool is provided for educational and research purposes. Use it responsibly and ensure you have the necessary permissions to analyze any files. The author is not responsible for any misuse of this script.
