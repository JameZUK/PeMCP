# Concept Reference: YARA Rule Authoring

Expert tier reference for Module 4.3. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

YARA is a pattern matching language used to identify and classify malware.
A YARA rule describes patterns — strings, byte sequences, conditions — that
characterise a malware family or variant. Writing effective YARA rules is the
bridge between analysis (understanding a single sample) and detection (finding
that sample and its variants across an entire environment or file repository).

Good YARA rules are specific enough to avoid false positives on legitimate
software, yet flexible enough to detect variants where the author has changed
minor details between builds.

## YARA Rule Structure

```yara
rule FamilyName_Variant : tag1 tag2 {
    meta:
        author = "analyst name"
        description = "Detects FamilyName variant based on ..."
        date = "2025-01-15"
        hash = "sha256 of the reference sample"
        tlp = "white"

    strings:
        $s1 = "unique string from the binary" ascii wide
        $s2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 } // hex pattern
        $s3 = /config_v[0-9]+\.dat/ nocase          // regex

    condition:
        uint16(0) == 0x5A4D and          // must be a PE
        filesize < 500KB and             // size constraint
        (2 of ($s*))                     // at least 2 of the strings
}
```

### Meta Section

Metadata for humans — does not affect matching. Always include:
- **author**: who wrote the rule
- **description**: what it detects and why (reference the analysis)
- **date**: when the rule was written
- **hash**: SHA256 of the sample that was used to develop the rule
- **tlp**: traffic light protocol classification

### Strings Section

Three string types:
- **Text strings**: `"text"` with optional `ascii`, `wide`, `nocase`, `fullword`
- **Hex patterns**: `{ 4D 5A 90 00 }` with wildcards `??` and jumps `[2-4]`
- **Regex**: `/pattern/` with optional `nocase`

### Condition Section

Boolean logic combining string matches, file properties, and positional checks:
- `any of ($s*)` — at least one string matches
- `2 of ($s*)` — at least two strings match
- `$s1 at 0` — string at specific offset
- `$s1 in (0..1024)` — string within a range
- `#s1 > 3` — string occurs more than 3 times
- `filesize < 1MB` — file size constraint
- `uint16(0) == 0x5A4D` — PE magic number check

## Choosing Good Strings

This is the art of YARA writing. Good strings are:

### Unique to the family

Strings that appear in this malware family and nowhere else. Examples:
- Custom mutex names: `"Global\\MyMalwareMutex_v3"`
- Campaign identifiers: `"campaign_2024Q4_target1"`
- Distinctive error messages: `"[!] Failed to inject payload into %s"`
- Custom protocol markers: `"BEACON_INIT|"`

### Not compiler-generated

Avoid strings that the compiler, runtime, or standard libraries produce:
- `"MSVCR140.dll"` — runtime dependency, present in millions of legitimate binaries
- `".text"`, `".data"` — standard section names
- `"GetProcAddress"` — common import, not distinctive
- Standard C++ exception strings, RTTI type names

### Stable across versions

Choose strings that are unlikely to change between minor updates:
- Internal function names or debug paths are good (authors rarely rename them)
- Hardcoded config field names or protocol command names are good
- Specific error message text is fragile (easily changed)

### Using Hex Patterns from Code Sequences

When unique strings are insufficient, use distinctive code patterns:

```
Tool: get_hex_dump(offset, length)

Examine the raw bytes of a unique function (e.g., a custom decryption routine
or an unusual API calling sequence).

Example: the decryption function at 0x00401A00 has a distinctive sequence:
  { 8B 45 08 33 45 0C 89 45 08 FF 4D 10 75 F4 }
  (xor loop with specific register usage pattern)
```

Use wildcards for addresses that change between builds:
```yara
$code = { 8B 45 ?? 33 45 ?? 89 45 ?? FF 4D ?? 75 F4 }
```

The `??` wildcards match any byte, so register offsets and local variable
positions can vary without breaking the rule.

```
Tool: compute_similarity_hashes()

Generate imphash and other similarity hashes. These can serve as additional
YARA conditions for high-confidence matching.
```

## Testing YARA Rules

### Testing Against the Sample

```
Tool: search_yara_custom(rule="rule Test { strings: $s1 = ... condition: ... }")

Test your rule against the currently loaded binary. Verify that it matches and
check which strings were found and at what offsets.

Example output:
  Rule "Test" matched!
  String hits:
    $s1 at offset 0x1A30 ("unique_mutex_name")
    $s2 at offset 0x3000 ({ 8B 45 08 33 45 0C ... })
    $s3 not found
  Condition: 2 of ($s*) = TRUE (2 of 3 matched)
```

### Avoiding False Positives

The biggest risk in YARA authoring is rules that match legitimate software.
Strategies to minimise false positives:

1. **Combine multiple indicators**: never rely on a single string. Use
   `2 of ($s*)` or more to require corroboration.
2. **Add file property constraints**: `filesize`, PE magic check, section count.
3. **Avoid generic patterns**: strings like `"password"`, `"http://"`, or
   `"error"` appear in too many legitimate binaries.
4. **Test against known-good files**: run the rule against a corpus of clean
   software (Windows system files, common applications).
5. **Use `fullword`**: prevents `"config"` from matching inside `"reconfigure"`.

### Iterative Refinement

YARA rule development is iterative:

1. Start broad — write a rule with the most distinctive strings
2. Test against the sample — confirm it matches
3. Test against clean files — check for false positives
4. Narrow — add conditions, replace generic strings with specific ones
5. Test against variants — if you have other samples from the same family,
   ensure the rule still matches (flexibility check)
6. Document — update meta section with reasoning for each string choice

## Rule Maintenance

YARA rules degrade over time as malware authors modify their code:

- **String rotation**: authors change mutex names, campaign IDs, user agents
- **Code changes**: refactoring alters byte patterns
- **Packing changes**: switching packers changes the outer layer entirely

Maintain rules by:
- Writing rules against the unpacked binary (packer-independent)
- Using code patterns in addition to strings (harder to change without
  rewriting the logic)
- Reviewing and updating rules when new variants are discovered
- Versioning rules and tracking which samples each version detects

## Socratic Questions

- "You found three unique strings in the binary. Which one would make the best
  YARA string, and why?"
  (Leads to: evaluating uniqueness, stability, and false positive risk)
- "Your rule matches the sample but also matches notepad.exe. What went wrong?"
  (Leads to: one of the strings is too generic, needs more specific patterns
  or additional conditions)
- "If the malware author changes the C2 domain in the next build, will your
  rule still detect it?"
  (Leads to: rules based on C2 domains are fragile, prefer code patterns and
  internal identifiers)
- "Should you write your YARA rule against the packed or unpacked version of
  the binary?"
  (Leads to: depends on the use case. For file scanning, the packed version is
  what exists on disk. For memory scanning, the unpacked version.)

## Common Mistakes

### Single-string rules

A rule with one string and no other conditions will produce false positives.
Always require at least two independent indicators or combine strings with
structural conditions (file size, PE header checks).

### Overly specific hex patterns

Using exact bytes for an entire function makes the rule break on the next
compiler version. Use wildcards for variable parts (register encodings, offsets,
addresses) and anchor on the distinctive operational bytes.

### Ignoring wide strings

Windows malware frequently uses UTF-16 (wide) strings. A rule that only checks
ASCII will miss the same string stored as wide characters. Use the `wide`
modifier or include both: `$s = "string" ascii wide`.

### Not documenting reasoning

Six months later, nobody (including you) will remember why each string was
chosen. Document the rationale in the meta section or as comments. Explain what
makes each string distinctive and which analysis finding it came from.
