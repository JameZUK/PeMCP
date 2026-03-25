"""Unit tests for _build_function_digest in tools_angr.py."""
import pytest

from arkana.mcp.tools_angr import _build_function_digest


# ---------------------------------------------------------------------------
# Basic Structure
# ---------------------------------------------------------------------------

class TestFunctionDigestBasics:
    """Test that _build_function_digest returns a well-formed dict."""

    def test_returns_required_keys(self):
        lines = ["int main(int argc, char** argv) {", "  return 0;", "}"]
        result = _build_function_digest(lines, "main", "0x401000")
        assert result["address"] == "0x401000"
        assert result["function_name"] == "main"
        assert "prototype" in result
        assert "api_calls" in result
        assert "strings" in result
        assert "patterns" in result
        assert "complexity" in result
        assert "one_liner" in result

    def test_empty_input(self):
        result = _build_function_digest([], "unknown", "0x0")
        assert result["prototype"] == ""
        assert result["api_calls"] == []
        assert result["strings"] == []
        assert result["patterns"] == []
        assert result["one_liner"] == "No notable patterns detected"
        assert result["complexity"]["lines"] == 0
        assert result["complexity"]["loops"] == 0
        assert result["complexity"]["branches"] == 0

    def test_comment_only_lines_skipped_for_prototype(self):
        lines = [
            "// Decompiled by angr",
            "/* Generated code */",
            "void sub_401000(void) {",
            "}",
        ]
        result = _build_function_digest(lines, "sub_401000", "0x401000")
        assert result["prototype"] == "void sub_401000(void) {"

    def test_blank_lines_skipped_for_prototype(self):
        lines = ["", "  ", "int foo(void) {", "}"]
        result = _build_function_digest(lines, "foo", "0x401000")
        assert "foo" in result["prototype"]


# ---------------------------------------------------------------------------
# API Call Extraction
# ---------------------------------------------------------------------------

class TestFunctionDigestCalls:
    """Test API call extraction from pseudocode."""

    def test_function_calls_extracted(self):
        lines = [
            "void malware() {",
            "  VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_RWX);",
            "  memcpy(dest, src, len);",
            "  CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, NULL);",
            "}",
        ]
        result = _build_function_digest(lines, "malware", "0x401000")
        call_names = [c["name"] for c in result["api_calls"]]
        assert "VirtualAlloc" in call_names
        assert "memcpy" in call_names
        assert "CreateRemoteThread" in call_names

    def test_c_keywords_skipped(self):
        lines = [
            "void test() {",
            "  if (x) { foo(); }",
            "  while (y) { bar(); }",
            "  for (i = 0; i < 10; i++) { baz(); }",
            "  switch (z) { }",
            "  return sizeof(int);",
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        call_names = [c["name"] for c in result["api_calls"]]
        assert "if" not in call_names
        assert "while" not in call_names
        assert "for" not in call_names
        assert "switch" not in call_names
        assert "sizeof" not in call_names
        # Actual function calls should be present
        assert "foo" in call_names
        assert "bar" in call_names
        assert "baz" in call_names

    def test_args_preview_included(self):
        lines = [
            "void test() {",
            "  memcpy(dest, src, 0x100);",
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        memcpy_calls = [c for c in result["api_calls"] if c["name"] == "memcpy"]
        assert len(memcpy_calls) >= 1
        assert memcpy_calls[0]["args_preview"] != ""
        assert "dest" in memcpy_calls[0]["args_preview"]

    def test_deduplicated_calls(self):
        lines = [
            "void test() {",
            "  foo(1);",
            "  foo(2);",
            "  foo(3);",
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        foo_calls = [c for c in result["api_calls"] if c["name"] == "foo"]
        assert len(foo_calls) == 1

    def test_calls_capped_at_30(self):
        lines = ["void test() {"]
        for i in range(50):
            lines.append(f"  func_{i}(arg);")
        lines.append("}")
        result = _build_function_digest(lines, "test", "0x401000")
        assert len(result["api_calls"]) <= 30


# ---------------------------------------------------------------------------
# String Literal Extraction
# ---------------------------------------------------------------------------

class TestFunctionDigestStrings:
    """Test string literal extraction from pseudocode."""

    def test_strings_extracted(self):
        lines = [
            "void test() {",
            '  char* url = "http://evil.com/c2";',
            '  char* path = "C:\\\\Windows\\\\Temp\\\\payload.exe";',
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        assert len(result["strings"]) == 2
        assert "http://evil.com/c2" in result["strings"]

    def test_short_strings_filtered(self):
        """Strings shorter than 4 chars should be excluded by the len >= 4 filter."""
        lines = [
            "void test() {",
            '  char* s2 = "abcdefgh";',
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "abcdefgh" in result["strings"]
        # Only strings with len >= 4 should appear
        for s in result["strings"]:
            assert len(s) >= 4, f"Short string {s!r} should have been filtered"

    def test_strings_capped_at_20(self):
        lines = ["void test() {"]
        for i in range(30):
            lines.append(f'  char* s{i} = "string_value_{i:04d}";')
        lines.append("}")
        result = _build_function_digest(lines, "test", "0x401000")
        assert len(result["strings"]) <= 20

    def test_deduplicated_strings(self):
        lines = [
            "void test() {",
            '  char* a = "repeated";',
            '  char* b = "repeated";',
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        assert result["strings"].count("repeated") == 1


# ---------------------------------------------------------------------------
# Pattern Detection
# ---------------------------------------------------------------------------

class TestFunctionDigestPatterns:
    """Test behavioural pattern detection."""

    def test_xor_operation(self):
        lines = ["void test() {", "  x = a ^ b;", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "xor_operation" in result["patterns"]

    def test_bit_shift(self):
        lines = ["void test() {", "  x = a >> 8;", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "bit_shift" in result["patterns"]

    def test_bitwise_not(self):
        lines = ["void test() {", "  x = ~a;", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "bitwise_not" in result["patterns"]

    def test_loop_detection(self):
        lines = ["void test() {", "  while (1) { x++; }", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "loop" in result["patterns"]

    def test_for_loop_detection(self):
        lines = ["void test() {", "  for (int i = 0; i < n; i++) {}", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "loop" in result["patterns"]

    def test_memory_allocation(self):
        lines = ["void test() {", "  p = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_RWX);", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "memory_allocation" in result["patterns"]

    def test_memory_copy(self):
        lines = ["void test() {", "  memcpy(dst, src, len);", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "memory_copy" in result["patterns"]

    def test_file_access(self):
        lines = ["void test() {", '  h = CreateFile("test.txt", ...);', "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "file_access" in result["patterns"]

    def test_network_activity(self):
        lines = ["void test() {", "  connect(sock, &addr, sizeof(addr));", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "network_activity" in result["patterns"]

    def test_registry_access(self):
        lines = ["void test() {", '  RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\test", 0, KEY_READ, &hKey);', "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "registry_access" in result["patterns"]

    def test_process_creation(self):
        lines = ["void test() {", '  CreateProcessA("cmd.exe", ...);', "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "process_creation" in result["patterns"]

    def test_process_injection(self):
        lines = [
            "void test() {",
            "  WriteProcessMemory(hProcess, addr, buf, len, NULL);",
            "  CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, NULL);",
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "process_injection" in result["patterns"]

    def test_crypto_operation(self):
        lines = ["void test() {", "  CryptEncrypt(hKey, 0, TRUE, 0, buf, &len, bufLen);", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "crypto_operation" in result["patterns"]

    def test_no_patterns_on_trivial_code(self):
        lines = ["int add(int a, int b) {", "  return a + b;", "}"]
        result = _build_function_digest(lines, "add", "0x401000")
        assert result["patterns"] == []


# ---------------------------------------------------------------------------
# Complexity Metrics
# ---------------------------------------------------------------------------

class TestFunctionDigestComplexity:
    """Test complexity metric extraction."""

    def test_line_count(self):
        lines = ["void f() {", "  x = 1;", "  y = 2;", "}"]
        result = _build_function_digest(lines, "f", "0x401000")
        assert result["complexity"]["lines"] == 4

    def test_loop_count(self):
        """Loop count uses word-boundary regex for while/for/do.
        Note: 'do {} while (b)' counts both 'do' and 'while' as separate matches."""
        lines = [
            "void f() {",
            "  while (a) {}",
            "  for (;;) {}",
            "  do {} while (b);",
            "}",
        ]
        result = _build_function_digest(lines, "f", "0x401000")
        # 'while' (line 2) + 'for' (line 3) + 'do' (line 4) + 'while' (line 4) = 4
        assert result["complexity"]["loops"] == 4

    def test_branch_count(self):
        lines = [
            "void f() {",
            "  if (a) {}",
            "  if (b) {} else {}",
            "}",
        ]
        result = _build_function_digest(lines, "f", "0x401000")
        assert result["complexity"]["branches"] == 2

    def test_block_count(self):
        lines = ["void f() {", "  {", "    {", "    }", "  }", "}"]
        result = _build_function_digest(lines, "f", "0x401000")
        assert result["complexity"]["blocks"] == 3


# ---------------------------------------------------------------------------
# One-Liner Summary
# ---------------------------------------------------------------------------

class TestFunctionDigestOneLiner:
    """Test one-liner summary generation."""

    def test_empty_produces_default(self):
        result = _build_function_digest([], "test", "0x401000")
        assert result["one_liner"] == "No notable patterns detected"

    def test_patterns_included_in_summary(self):
        lines = ["void test() {", "  x = a ^ b;", "  while (1) {}", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "Patterns:" in result["one_liner"]
        assert "xor_operation" in result["one_liner"]

    def test_calls_included_in_summary(self):
        lines = ["void test() {", "  VirtualAlloc(NULL, 0x1000, 0, 0);", "}"]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "Calls:" in result["one_liner"]
        assert "VirtualAlloc" in result["one_liner"]

    def test_strings_count_in_summary(self):
        lines = [
            "void test() {",
            '  char* a = "hello world";',
            '  char* b = "another string";',
            "}",
        ]
        result = _build_function_digest(lines, "test", "0x401000")
        assert "Strings:" in result["one_liner"]

    def test_complex_function_summary(self):
        """A function with patterns, calls, and strings should have a multi-part summary."""
        lines = [
            "void dropper() {",
            '  HANDLE h = CreateFileA("C:\\\\temp\\\\payload.dll", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);',
            "  for (int i = 0; i < len; i++) {",
            "    buf[i] = buf[i] ^ key;",
            "  }",
            "  WriteFile(h, buf, len, &written, NULL);",
            "}",
        ]
        result = _build_function_digest(lines, "dropper", "0x401000")
        assert "Patterns:" in result["one_liner"]
        assert "Calls:" in result["one_liner"]
