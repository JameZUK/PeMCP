# Concept Reference: String Analysis

Foundation tier reference for Module 1.3. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Strings are sequences of readable characters embedded in a binary. They are among
the fastest and most accessible sources of intelligence when analysing an unknown
file. Programmers embed strings for error messages, debug output, file paths, URLs,
registry keys, command names, and more — and these strings survive compilation,
offering a window into the binary's purpose and behaviour.

### The Notebook Analogy

Use this analogy to frame string analysis for beginners:

"Imagine you find a stranger's notebook. You cannot read the handwriting (the
machine code), but scattered throughout are printed labels, sticky notes, phone
numbers, and addresses (the strings). You can learn a lot about what this person
does — where they go, who they contact, what tools they use — just from reading
those notes, even without understanding the handwriting around them."

Extend the analogy:
- **Printed labels** = hardcoded strings the programmer intentionally included
- **Sticky notes in code** = debug and error messages left during development
- **Phone numbers and addresses** = URLs, IPs, file paths — operational strings
- **Notes in a foreign alphabet** = wide strings (UTF-16) — same information,
  different encoding
- **Notes written in invisible ink** = encoded or encrypted strings — deliberate
  concealment
- **Random scribbles** = false positives — byte sequences that happen to look
  like readable text but are not meaningful strings

## String Types

### ASCII Strings

Standard single-byte character encoding. Most string extraction tools look for
sequences of 4+ printable ASCII bytes (0x20-0x7E) followed by a null terminator.
This is the default and most common type.

### Wide Strings (UTF-16LE)

Windows APIs extensively use wide strings (2 bytes per character, little-endian).
A wide string "hello" appears in hex as: `68 00 65 00 6C 00 6C 00 6F 00 00 00`.
The alternating null bytes are the signature pattern.

Key teaching point: if a binary targets Windows and you only search for ASCII
strings, you will miss every string passed to a W-suffix API (CreateFileW,
RegOpenKeyExW, MessageBoxW, etc.). Always check both.

### Stack Strings

Strings constructed character-by-character at runtime by pushing or moving
individual bytes onto the stack. They do not appear in static string extraction
because they never exist as a contiguous sequence in the file. FLOSS
(FireEye Labs Obfuscated String Solver) can recover these through emulation.

### Encoded/Encrypted Strings

Strings deliberately hidden from static analysis. Common methods:
- **Base64** — recognisable by character set (A-Za-z0-9+/=) and padding (=, ==)
- **XOR** — each byte XORed with a key; single-byte XOR produces visible patterns
  (e.g., XOR 0x41 turns "http" into ")++1")
- **Custom encoding** — ROT13, character substitution, compression, AES encryption

## Operationally Significant String Categories

Teach the learner to look for these categories during triage:

| Category | Examples | What It Suggests |
|----------|----------|-----------------|
| **URLs / Domains** | `http://evil.com/gate.php`, `update.malware[.]xyz` | Network communication, C2 |
| **IP Addresses** | `192.168.1.100`, `10.0.0.1:4444` | Hardcoded C2 or callback addresses |
| **File Paths** | `C:\Users\Public\payload.exe`, `%TEMP%\dropper.dll` | File drop locations |
| **Registry Keys** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Persistence mechanisms |
| **Mutex Names** | `Global\MyMalwareMutex`, `{GUID-HERE}` | Single-instance enforcement |
| **Error Messages** | `Failed to connect`, `Invalid key length` | Debug info revealing logic |
| **API Names** | `VirtualAllocEx`, `InternetOpenUrl` | Dynamic API resolution hints |
| **Commands** | `cmd.exe /c`, `powershell -enc`, `whoami` | Command execution behaviour |
| **Crypto Markers** | `-----BEGIN RSA PRIVATE KEY-----`, `AES-256-CBC` | Cryptographic operations |
| **User-Agent Strings** | `Mozilla/5.0 (compatible; MSIE...` | Network request disguise |

## Key Arkana Tools

- **`get_strings_summary()`** — The primary tool. Returns strings pre-categorised
  by type (URLs, IPs, paths, registry keys, mutexes, crypto markers, etc.) with
  counts and representative examples. Always start here.
- **`search_for_specific_strings(patterns=[...])`** — Targeted regex search. Use
  when you know what you are looking for (e.g., specific domain patterns, known
  mutex names, or custom indicators).
- **`get_top_sifted_strings()`** — ML-ranked strings sorted by likely relevance.
  Surfaces the most operationally significant strings from the noise. Good for
  the learner to see how automated relevance ranking works.
- **`get_floss_analysis_info()`** — FLOSS results showing three classes of
  recovered strings: static (normal extraction), stack strings (constructed at
  runtime), and decoded strings (deobfuscated). Teach the difference between
  these three classes.
- **`extract_wide_strings()`** — Dedicated UTF-16/wide string extraction. Use to
  show the learner what ASCII-only extraction misses.

### Teaching Moment: Comparing Tools

A powerful exercise is running `get_strings_summary()` followed by
`get_floss_analysis_info()` on the same binary. The difference between the two
results demonstrates why simple string extraction is insufficient for obfuscated
binaries. FLOSS recovers strings that static extraction cannot see.

## Socratic Questions

- "Why might a legitimate program contain URLs?"
  (Expected insight: update checks, telemetry, documentation links, license
  validation — URLs alone do not prove malicious intent)
- "What could this mutex name tell us about the binary?"
  (Expected insight: mutexes prevent multiple instances; the name might be a
  unique identifier, a family signature, or a campaign marker)
- "We found the string 'cmd.exe /c del %0' — what do you think that does?"
  (Expected insight: self-deletion — the binary deletes itself after execution)
- "This binary has very few readable strings. What might explain that?"
  (Expected insight: packing, encryption, or string obfuscation — or it could
  genuinely be a small utility with minimal text output)
- "We see base64-encoded data in the strings. Why would someone encode strings
  in their own program?"
  (Expected insight: to evade string-based detection signatures and make static
  analysis harder; or for legitimate data serialisation)
- "The string 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' appeared. Why
  is this particular registry key interesting?"
  (Expected insight: programs listed under this key run automatically at login
  — it is a classic persistence mechanism)

## Common Misconceptions

### "All strings in a binary are relevant"

Most binaries contain hundreds or thousands of strings. The vast majority are
compiler-generated boilerplate, library messages, format specifiers, and other
noise. Teach learners to focus on operationally significant categories rather
than reading every string. `get_top_sifted_strings()` helps by ranking strings
by likely relevance.

### "Absence of strings means the binary is packed"

Low string count is one indicator of packing, but it is not definitive. Some
legitimate programs are genuinely small. Packing is confirmed by the combination
of low string count AND high entropy AND low import count AND potentially PEiD
matches. Always correlate multiple indicators. A binary could also have few
strings because it is a driver, a shared library, or simply a small tool.

### "If I can see a URL, the binary definitely connects to it"

Strings show what is present in the binary, not what the binary does with them.
A URL might be in dead code, a commented-out feature, an embedded resource that
is never accessed, or a library that includes it but the program never calls. To
confirm network behaviour, you need to trace code references to the string and
verify it is passed to a network API.

### "Wide strings are exotic or unusual"

On Windows, wide strings are the norm for anything touching the OS. Windows NT
and later are natively Unicode. Many APIs exist in both A (ANSI) and W (Wide)
variants. Modern software overwhelmingly uses the W variants. Failing to extract
wide strings means missing a large portion of the binary's text.

### "Encrypted strings cannot be recovered"

While statically encrypted strings do not appear in basic extraction, multiple
techniques can recover them: FLOSS emulation-based decoding, runtime emulation
with Qiling/Speakeasy followed by memory search, XOR brute-forcing for simple
ciphers, and manual decryption once the algorithm and key are identified. The
strings are hidden, not gone.

## When to Teach This

- **Immediately after binary-basics**: String analysis requires almost no
  prerequisite knowledge and provides immediate, tangible results. It is the
  best "quick win" for new learners.
- **During initial triage**: When `get_strings_summary()` output is on screen,
  walk through each category and what it reveals.
- **When strings are suspiciously absent**: If a binary has very few strings,
  use it as a bridge to the packing concept (Module 2.3).
- **When encoded strings appear**: Base64 blobs or XOR artifacts are natural
  bridges to deobfuscation concepts (Tier 2).
- **When a specific string raises questions**: Any interesting string the learner
  notices during analysis is a teaching moment for the relevant category.
