# Crypto Pattern Recognition

Reference material for Module 2.4. Builds on Foundation knowledge of decompiler
output and string extraction. This concept teaches learners to recognise common
cryptographic implementations in binaries and understand what they protect.

---

## Core Concepts

### Why Crypto Appears in Binaries

**Legitimate uses**: TLS/SSL for secure communication, password hashing for
authentication, file encryption for data protection, digital signature verification,
license key validation.

**Malicious uses**: Encrypting C2 communication to evade network detection, hiding
configuration data (C2 addresses, credentials) from static analysis, encrypting
strings to defeat signature-based detection, ransomware file encryption, obfuscating
exfiltrated data.

The presence of crypto is not inherently suspicious — what matters is WHAT is being
encrypted and WHY. A binary that encrypts files on disk while communicating with a
hardcoded IP address is behaving very differently from one that validates TLS
certificates.

### XOR Encryption

XOR is the simplest "encryption" found in malware. It is fast, trivial to implement,
and requires no crypto libraries.

**Single-byte XOR**: Every byte is XORed with the same key byte (`data[i] ^ 0x5A`).
In disassembly, look for a loop with `xor` using a byte-sized immediate.

**Multi-byte XOR**: A key of N bytes is applied cyclically (`data[i] ^ key[i % N]`).
Harder to spot because the key is loaded from memory rather than as an immediate.

**Recognising XOR in decompiled code**: Look for the `^` operator applied to byte
arrays in a loop. Single-byte XOR uses a constant; multi-byte uses indexed key bytes.

**Weaknesses**: XOR is trivially breakable. Known-plaintext attacks work instantly.
Single-byte XOR has only 256 possible keys — `brute_force_simple_crypto()` automates this.

### RC4

RC4 is a stream cipher commonly found in malware because it is simple to implement
(about 20 lines of C) and requires no block padding. It has two phases:

**KSA (Key Schedule Algorithm)**: Initialises a 256-byte state array by filling it
with values 0-255 and then performing a 256-iteration swap loop based on the key:
`j = (j + S[i] + key[i % keylen]) % 256; swap(S[i], S[j])`.

**PRGA (Pseudo-Random Generation Algorithm)**: Generates the keystream by continually
swapping state array elements and XORing output bytes with the data.

**How to recognise RC4**: The tell-tale sign is the 256-byte array initialisation
(`for i = 0 to 255: S[i] = i`) followed by a swap loop. The number 256 (0x100)
appears repeatedly in the decompiled code.

### AES

AES (Advanced Encryption Standard, also called Rijndael) is the most common
legitimate cipher and appears in sophisticated malware as well.

**SubBytes S-box**: AES uses a fixed 256-byte substitution table. The first few
values are: `0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5`. Finding this byte
sequence in a binary's data section is a strong indicator of AES.

**Rijndael key schedule**: Uses round constants (rcon): `0x01, 0x02, 0x04, 0x08,
0x10, 0x20, 0x40, 0x80, 0x1B, 0x36`. These constants in data sections or as
immediate values in code indicate AES key expansion.

**How to recognise AES**: `detect_crypto_constants()` scans for the SubBytes S-box
and round constants automatically. In decompiled code, look for 16-byte block
operations, 10/12/14-round loops (for 128/192/256-bit keys), and references to
the S-box table.

AES in malware typically uses the Windows CryptoAPI (`CryptEncrypt`, `CryptDecrypt`)
or embedded implementations. CryptoAPI usage is visible in imports; embedded
implementations require constant detection.

### Crypto Constants vs Runtime-Derived Keys

A crucial distinction for analysis:

**Crypto constants**: Fixed values that identify the algorithm — S-boxes, round
constants, initialization vectors for known algorithms. These are structural and
do not change between samples. They tell you WHICH algorithm is used.

**Keys**: The secret values that parameterise the algorithm. Keys can be:
- **Hardcoded**: Embedded directly in the binary as byte arrays or strings. Easiest
  to extract — use `auto_extract_crypto_keys()`.
- **Derived**: Computed from a password or other input using a key derivation
  function (PBKDF2, scrypt). The password may be hardcoded even if the key is not.
- **Fetched**: Downloaded from a C2 server or read from a file at runtime. These
  cannot be recovered statically — emulation or network capture is needed.

### Where Keys Are Stored

Finding the key is often harder than identifying the algorithm. Common locations:
immediate values in code, byte arrays in `.data`/`.rdata` sections, PE resources,
derived from PE metadata (timestamp, file hash), hardcoded password strings passed
to KDFs, or embedded as the first/last N bytes of the encrypted blob itself.

---

## Key Arkana Tools

| Tool | Purpose |
|------|---------|
| `identify_crypto_algorithm()` | Detect crypto constants and algorithm signatures across the binary |
| `detect_crypto_constants()` | Scan specifically for known S-boxes, round constants, and magic values |
| `auto_extract_crypto_keys()` | Attempt to extract embedded encryption keys automatically |
| `decompile_function_with_angr(address)` | Read the crypto implementation to understand algorithm and key usage |

---

## Teaching Moments During Guided Analysis

**When crypto constants are detected**: Show the learner what was found and explain
which algorithm it identifies. Decompile the function that references the constants
to confirm the algorithm and understand how it is called.

**When an XOR loop is found in decompiled code**: Walk through the XOR pattern.
Ask whether it is single-byte or multi-byte. If single-byte, demonstrate using
`brute_force_simple_crypto()` to recover the key. If multi-byte, trace the key source
using `get_reaching_definitions()`.

**When encrypted data is found but the algorithm is unknown**: This is a natural
investigation exercise. Start with `identify_crypto_algorithm()` for constants, then
decompile functions near the encrypted data to find the decryption routine, then
trace the key.

**When distinguishing crypto from encoding**: Base64 is not encryption — it is
encoding. XOR with a known key is extremely weak "encryption." AES with a random
key is real encryption. Help the learner build a mental hierarchy of protection
strength.

---

## Socratic Questions

- "Is this XOR or something more complex?"
  *Expected direction*: Check the decompiled loop. Single operation per byte with
  `^` is XOR. If there is a state array, swap operations, or multi-round
  processing, it is something more complex (RC4, AES, etc.).

- "Where do you think the decryption key comes from?"
  *Expected direction*: Trace the key parameter backward. Is it a constant in the
  code? Loaded from a data section? Derived from a string? Fetched from the
  network? Use `get_reaching_definitions()` to find the key's origin.

- "This function has the AES S-box but does not call any CryptoAPI functions. Why?"
  *Expected direction*: The malware has its own AES implementation compiled into the
  binary, rather than using Windows APIs. This avoids import-based detection and
  makes the binary self-contained.

- "If we find the encryption key, what should we try to decrypt first?"
  *Expected direction*: Strings and configuration data. Encrypted strings often
  contain C2 addresses, credentials, or operational parameters. Use
  `refinery_decrypt()` with the recovered key and check if the output contains
  readable IOCs.

---

## Common Mistakes

**Assuming all XOR is crypto**: XOR is used for many non-cryptographic purposes in
compiled code — clearing registers (`xor eax, eax`), computing checksums, hash
functions, and compiler-generated code. Not every XOR instruction is an encryption
operation. Look for XOR applied to data buffers in loops, not isolated XOR
instructions.

**Missing multi-byte XOR keys**: Single-byte XOR is easy to spot (constant immediate
operand). Multi-byte XOR loads key bytes from memory in a loop, making the key less
visible. The key array must be traced through data flow analysis. Frequency analysis
on the ciphertext can also reveal key length.

**Not distinguishing crypto from encoding**: Base64 is not encryption. Hex encoding
is not encryption. These are reversible transformations that provide no security.
Malware often layers encoding on top of encryption (Base64(AES(plaintext))). Each
layer must be identified and removed in the correct order.

**Confusing algorithm identification with key recovery**: Knowing that a binary uses
AES-256-CBC tells you HOW the data is protected but not the key needed to decrypt
it. Algorithm identification is step one; key recovery is step two — and often the
harder step.

**Overlooking custom or modified algorithms**: Some malware modifies standard
algorithms (custom S-boxes, modified round counts, non-standard key schedules).
`detect_crypto_constants()` may not match these variants. If the code looks like
crypto but no known constants match, it may be a custom implementation that requires
manual analysis of the decompiled code.
