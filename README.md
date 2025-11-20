# **PeMCP Toolkit \- Advanced PE Analysis & Decompilation Suite**

The **PeMCP Toolkit** is a professional-grade Python suite designed for the in-depth static and dynamic analysis of Portable Executable (PE) files and raw shellcode. While it serves as a powerful CLI tool for generating comprehensive reports, its primary strength lies in its **Model-Context-Protocol (MCP) Server** mode.  
In MCP mode, PeMCP acts as an intelligent backend for LLMs (like Claude or other AI agents), providing them with a suite of **40+ specialized tools** to interactively explore, decompile, and analyze binaries. It bridges the gap between high-level AI reasoning and low-level binary instrumentation.

# **Key Features**

### **1\. Advanced Binary Analysis (Powered by Angr)**

Beyond standard static analysis, PeMCP now integrates the **Angr** binary analysis framework to provide capabilities typically reserved for dedicated reverse engineering platforms:

* **Decompilation**: Convert assembly into human-readable C-like pseudocode on the fly.  
* **Control Flow Graph (CFG)**: Generate and traverse function blocks and edges.  
* **Symbolic Execution**: Automatically find inputs to reach specific code paths (e.g., "Find an input that reaches the 'Access Granted' block").  
* **Emulation**: Execute functions with concrete arguments using the Unicorn engine to observe behavior safely.  
* **Slicing & Dominators**: Perform forward/backward slicing to track data flow and identify critical code dependencies.

### **2\. Comprehensive Static Analysis**

* **PE Structure**: Full parsing of DOS/NT Headers, Imports/Exports, Resources, TLS, Debug, and Load Config.  
* **Signatures**: Authenticode validation (Signify), certificate parsing (Cryptography), and Packer detection (PEiD).  
* **Capabilities**: Integrated **Capa** analysis to map binary behaviors to the MITRE ATT\&CK framework.  
* **Strings**: **FLOSS** integration for extracting static, stack, tight, and decoded strings, ranked by relevance using **StringSifter**.

### **3\. Robust Architecture**

* **Docker-First Design**: No interactive prompts. Dependencies are managed via environment or Docker, making it CI/CD and container-ready.  
* **State Encapsulation**: Uses a centralized AnalyzerState class to manage analysis context, ensuring thread safety and stability.  
* **Background** Task **Management**: Long-running operations (like symbolic execution) run asynchronously with a heartbeat monitor, preventing timeouts.

## **Prerequisites and Installation**

### **Option A: Docker (Recommended)**

The easiest way to run PeMCP is via Docker. This handles all complex dependencies (Angr, Unicorn, Vivisect) automatically.

1. **Build the Image**:  
   docker build \-t pemcp-toolkit .

2. **Run** as MCP **Server**:  
   \# Create a directory for your malware samples  
   mkdir \-p ./samples

   \# Run the container  
   docker run \--rm \-it \\  
     \-p 8082:8082 \\  
     \-v "$(pwd)/samples:/app/samples" \\  
     \-e VT\_API\_KEY="your\_virustotal\_key" \\  
     pemcp-toolkit \\  
     \--mcp-server \\  
     \--input-file /app/samples/suspicious.exe \\  
     \--mcp-host 0.0.0.0

### **Option B: Local Installation**

If you prefer running locally, you must have Python 3.10+ and cmake installed (for building Unicorn/Angr bindings).

1. **Install System Dependencies (Ubuntu/Debian)**:  
   sudo apt-get install build-essential libssl-dev cmake

2. **Install Python Packages**:  
   pip install \-r requirements.txt

   *Note: Ensure pefile, angr\[unicorn\], flare-floss, flare-capa, rapidfuzz, and mcp\[cli\] are installed.*

## **Modes of Operation**

### **1\. CLI Mode (One-Shot Report)**

Best for generating a massive, human-readable dump of all static data found in a file.  
python PeMCP.py \--input-file malware.exe \--verbose \> analysis\_report.txt

**Capabilities in CLI Mode:**

* Full PE header dump.  
* Hashes (MD5, SHA256, SSDeep).  
* YARA & PEiD scans.  
* Capa capability report.  
* FLOSS string extraction.

### **2\. MCP Server Mode (Interactive Agent)**

Best for use with AI coding assistants or MCP clients. The server pre-loads the binary and exposes tools to query it dynamically.  
python PeMCP.py \--mcp-server \--input-file malware.exe

#### **Available Tools (Highlights)**

**🔍 Deep Binary Analysis (Angr)**

* decompile\_function\_with\_angr: Returns C-like pseudocode for a specific address.  
* find\_path\_to\_address: Uses symbolic execution to solve for inputs that reach a target instruction.  
* emulate\_function\_execution: Runs a function with specific arguments in a sandboxed emulator.  
* get\_function\_cfg: Returns the nodes and edges of a function's control flow graph.  
* get\_backward\_slice / get\_forward\_slice: Traces code reachability.  
* analyze\_binary\_loops: Detects and characterizes loops in the binary.

**🧪 Triage & Forensics**

* get\_triage\_report: Auto-generates a summary of high-value indicators (suspicious imports, high-score strings, severe capabilities).  
* get\_virustotal\_report\_for\_loaded\_file: Queries VirusTotal for the file hash (requires VT\_API\_KEY).  
* reanalyze\_loaded\_pe\_file: Triggers a re-scan (e.g., to enable Angr features if skipped initially).

**📝 String & Data Analysis**

* get\_top\_sifted\_strings: Returns strings ranked by "interestingness" (using Machine Learning).  
* fuzzy\_search\_strings: Finds strings similar to a query (great for finding obfuscated keys).  
* find\_and\_decode\_encoded\_strings: Detects Base64/Hex/XOR patterns and attempts heuristic decoding.  
* search\_floss\_strings: Regex search over FLOSS-extracted strings (stack, tight, decoded).

**🧬 Context & Linking**

* get\_string\_usage\_context: Shows the assembly instructions around where a string is used.  
* get\_strings\_for\_function: Lists all strings referenced by a specific function.

## **Configuration**

### **Environment Variables**

* VT\_API\_KEY: (Optional) Your VirusTotal API key. Required for the get\_virustotal\_report\_for\_loaded\_file tool.

### **Shellcode Analysis**

PeMCP supports raw shellcode analysis. When using raw binaries:

1. Use \--mode shellcode.  
2. Ideally provide an architecture hint to FLOSS/Angr using \--floss-format sc64 (or sc32).

python PeMCP.py \--mcp-server \--input-file shellcode.bin \--mode shellcode \--floss-format sc64

## **Architecture & Design**

* **Single-File Analysis Context**: The server holds one file in memory (AnalyzerState). All tools operate on this shared context, ensuring consistency.  
* **Lazy Loading**: Heavy analysis (like Angr CFG generation) can be triggered in the background or on-demand to allow for instant server startup.  
* **Smart Truncation**: MCP responses are automatically protected against token-limit overflows. If a tool returns 1MB of JSON, the server intelligently truncates lists or strings to fit within 64KB limits while preserving structural integrity.

## **Contributing**

Contributions are welcome\!

1. Fork the repository.  
2. Create a feature branch (git checkout \-b feature/AngrEnhancement).  
3. Commit your changes.  
4. Push to the branch.  
5. Open a Pull Request.

## **License**

Distributed under the MIT License. See LICENSE for more information.

## **Disclaimer**

This toolkit is provided "as-is" for educational and research purposes only. It is capable of executing parts
