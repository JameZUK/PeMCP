"""Tests for Go ABI detection and call annotation helpers."""
import unittest

from arkana.mcp._go_abi import (
    _parse_go_version,
    annotate_go_call,
    detect_go_abi,
    is_cgo_function,
    is_go_binary,
    is_go_function,
    _AMD64_INT_REGS,
    _ARM64_INT_REGS,
    _CLOSURE_PATTERN,
    _DETECTION_THRESHOLD,
    _RUNTIME_INTERNAL,
)


class TestParseGoVersion(unittest.TestCase):
    """Tests for Go version string parsing."""

    def test_standard_version(self):
        self.assertEqual(_parse_go_version("go1.21.5"), (1, 21))

    def test_version_without_prefix(self):
        self.assertEqual(_parse_go_version("1.17"), (1, 17))

    def test_rc_version(self):
        self.assertEqual(_parse_go_version("go1.18rc1"), (1, 18))

    def test_beta_version(self):
        self.assertEqual(_parse_go_version("go1.20beta1"), (1, 20))

    def test_old_version(self):
        self.assertEqual(_parse_go_version("go1.2"), (1, 2))

    def test_empty_string(self):
        self.assertIsNone(_parse_go_version(""))

    def test_none_input(self):
        self.assertIsNone(_parse_go_version(None))

    def test_garbage_string(self):
        self.assertIsNone(_parse_go_version("not-a-version"))

    def test_partial_version(self):
        self.assertIsNone(_parse_go_version("go"))

    def test_numeric_string(self):
        self.assertIsNone(_parse_go_version("42"))

    def test_version_with_patch(self):
        self.assertEqual(_parse_go_version("go1.22.3"), (1, 22))


class TestIsGoFunction(unittest.TestCase):
    """Tests for Go function name pattern matching."""

    def test_simple_function(self):
        self.assertTrue(is_go_function("main.main"))

    def test_package_function(self):
        self.assertTrue(is_go_function("fmt.Println"))

    def test_nested_package(self):
        self.assertTrue(is_go_function("crypto/tls.Dial"))

    def test_method_on_pointer(self):
        self.assertTrue(is_go_function("net/http.(*Client).Do"))

    def test_runtime_function(self):
        self.assertTrue(is_go_function("runtime.mallocgc"))

    def test_type_descriptor(self):
        self.assertTrue(is_go_function("type:.eq.main.Config"))

    def test_cgo_bridge_rejected(self):
        self.assertFalse(is_go_function("_cgo_topofstack"))

    def test_Cgo_bridge_rejected(self):
        self.assertFalse(is_go_function("_Cgo_use"))

    def test_plain_c_function(self):
        self.assertFalse(is_go_function("printf"))

    def test_sub_address(self):
        self.assertFalse(is_go_function("sub_401000"))

    def test_empty_string(self):
        self.assertFalse(is_go_function(""))

    def test_none_input(self):
        self.assertFalse(is_go_function(None))

    def test_numeric_input(self):
        self.assertFalse(is_go_function(123))

    def test_closure(self):
        self.assertTrue(is_go_function("main.main.func1"))

    def test_deep_package(self):
        self.assertTrue(is_go_function("github.com/user/repo/pkg.Function"))


class TestIsCgoFunction(unittest.TestCase):
    """Tests for CGO bridge function detection."""

    def test_cgo_prefix(self):
        self.assertTrue(is_cgo_function("_cgo_topofstack"))

    def test_Cgo_prefix(self):
        self.assertTrue(is_cgo_function("_Cgo_use"))

    def test_x_cgo_prefix(self):
        self.assertTrue(is_cgo_function("x_cgo_init"))

    def test_cgoexp_prefix(self):
        self.assertTrue(is_cgo_function("_cgoexp_GoFunc"))

    def test_go_function_not_cgo(self):
        self.assertFalse(is_cgo_function("main.main"))

    def test_empty(self):
        self.assertFalse(is_cgo_function(""))

    def test_none(self):
        self.assertFalse(is_cgo_function(None))


class TestIsGoBinary(unittest.TestCase):
    """Tests for Go binary heuristic detection."""

    def test_mostly_go_names(self):
        names = [
            "main.main", "main.init", "runtime.mallocgc",
            "fmt.Println", "os.Exit", "net/http.ListenAndServe",
        ]
        self.assertTrue(is_go_binary(names))

    def test_no_go_names(self):
        names = ["sub_401000", "printf", "main", "WinMain", "_start"]
        self.assertFalse(is_go_binary(names))

    def test_mixed_below_threshold(self):
        # Only 1 Go name out of 10 — below 0.3 threshold
        names = ["main.main"] + [f"sub_{i:06x}" for i in range(9)]
        self.assertFalse(is_go_binary(names))

    def test_mixed_above_threshold(self):
        # 4 Go names out of 10 — above 0.3 threshold
        go_names = ["main.main", "main.init", "runtime.mallocgc", "fmt.Println"]
        c_names = [f"sub_{i:06x}" for i in range(6)]
        self.assertTrue(is_go_binary(go_names + c_names))

    def test_empty_list(self):
        self.assertFalse(is_go_binary([]))

    def test_single_go_name(self):
        # 1 out of 1 — above threshold
        self.assertTrue(is_go_binary(["main.main"]))

    def test_single_non_go_name(self):
        self.assertFalse(is_go_binary(["printf"]))

    def test_samples_capped(self):
        # Only first 50 names should be sampled
        names = [f"main.func{i}" for i in range(100)]
        self.assertTrue(is_go_binary(names))


class TestDetectGoAbi(unittest.TestCase):
    """Tests for Go ABI version detection."""

    def test_amd64_register_abi(self):
        self.assertEqual(detect_go_abi("go1.21.5", "amd64"), "register")

    def test_amd64_exact_threshold(self):
        self.assertEqual(detect_go_abi("go1.17", "amd64"), "register")

    def test_amd64_stack_abi(self):
        self.assertEqual(detect_go_abi("go1.16", "amd64"), "stack")

    def test_amd64_old_version(self):
        self.assertEqual(detect_go_abi("go1.10", "amd64"), "stack")

    def test_arm64_register_abi(self):
        self.assertEqual(detect_go_abi("go1.18", "arm64"), "register")

    def test_arm64_stack_abi(self):
        self.assertEqual(detect_go_abi("go1.17", "arm64"), "stack")

    def test_x86_always_stack(self):
        self.assertEqual(detect_go_abi("go1.21", "x86"), "stack")

    def test_i386_always_stack(self):
        self.assertEqual(detect_go_abi("go1.21", "i386"), "stack")

    def test_arm32_always_stack(self):
        self.assertEqual(detect_go_abi("go1.21", "arm"), "stack")

    def test_x86_64_normalised(self):
        self.assertEqual(detect_go_abi("go1.21", "x86_64"), "register")

    def test_aarch64_normalised(self):
        self.assertEqual(detect_go_abi("go1.18", "aarch64"), "register")

    def test_unknown_version(self):
        self.assertEqual(detect_go_abi("", "amd64"), "unknown")

    def test_unknown_arch(self):
        self.assertEqual(detect_go_abi("go1.21", "sparc"), "unknown")

    def test_mips_always_stack(self):
        self.assertEqual(detect_go_abi("go1.21", "mips"), "stack")

    def test_none_version(self):
        self.assertEqual(detect_go_abi(None, "amd64"), "unknown")


class TestAnnotateGoCall(unittest.TestCase):
    """Tests for Go call-site annotation generation."""

    def test_register_abi_amd64(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               go_version_hint="go1.21")
        self.assertIsNotNone(ann)
        self.assertEqual(ann["convention"], "register")
        self.assertIn("params", ann)
        self.assertIn("returns", ann)
        self.assertTrue(len(ann["params"]) > 0)
        # First param should be in rax
        self.assertEqual(ann["params"][0]["register"], "rax")
        self.assertEqual(ann["params"][0]["index"], 0)

    def test_stack_abi(self):
        ann = annotate_go_call("main.encrypt", "stack", "amd64",
                               go_version_hint="go1.16")
        self.assertIsNotNone(ann)
        self.assertEqual(ann["convention"], "stack")
        self.assertIn("stack_offset", ann["params"][0])
        self.assertEqual(ann["params"][0]["stack_offset"], "[RSP+0x8]")

    def test_non_go_function_returns_none(self):
        ann = annotate_go_call("printf", "register", "amd64")
        self.assertIsNone(ann)

    def test_cgo_function_returns_none(self):
        ann = annotate_go_call("_cgo_topofstack", "register", "amd64")
        self.assertIsNone(ann)

    def test_runtime_internal_returns_none(self):
        for name in _RUNTIME_INTERNAL:
            ann = annotate_go_call(name, "register", "amd64")
            self.assertIsNone(ann, f"Expected None for runtime internal {name}")

    def test_empty_name_returns_none(self):
        ann = annotate_go_call("", "register", "amd64")
        self.assertIsNone(ann)

    def test_none_name_returns_none(self):
        ann = annotate_go_call(None, "register", "amd64")
        self.assertIsNone(ann)

    def test_closure_annotation(self):
        ann = annotate_go_call("main.main.func1", "register", "amd64",
                               go_version_hint="go1.21")
        self.assertIsNotNone(ann)
        self.assertTrue(ann.get("closure", False))
        self.assertIn("closure", ann["note"].lower())

    def test_max_params_clamped(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               max_params=3)
        self.assertEqual(len(ann["params"]), 3)

    def test_max_params_clamped_to_1(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               max_params=0)
        self.assertEqual(len(ann["params"]), 1)

    def test_max_params_upper_bound(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               max_params=100)
        # Should be clamped to 20, then to register count (9 for amd64)
        self.assertTrue(len(ann["params"]) <= 20)

    def test_arm64_register_abi(self):
        ann = annotate_go_call("main.process", "register", "arm64",
                               go_version_hint="go1.18")
        self.assertIsNotNone(ann)
        self.assertEqual(ann["convention"], "register")
        self.assertEqual(ann["params"][0]["register"], "r0")

    def test_stack_abi_32bit(self):
        ann = annotate_go_call("main.process", "stack", "x86",
                               go_version_hint="go1.16")
        self.assertIsNotNone(ann)
        # 32-bit slots are 4 bytes
        self.assertEqual(ann["params"][0]["stack_offset"], "[RSP+0x4]")

    def test_with_type_info(self):
        type_info = {
            "methods": {
                "main.encrypt": {
                    "params": [
                        {"name": "data", "type": "[]byte"},
                        {"name": "key", "type": "[32]byte"},
                    ]
                }
            }
        }
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               type_info=type_info)
        self.assertEqual(ann["params"][0].get("name"), "data")
        self.assertEqual(ann["params"][0].get("type"), "[]byte")

    def test_with_type_info_partial(self):
        """Type info has fewer params than max_params."""
        type_info = {
            "methods": {
                "main.encrypt": {
                    "params": [{"name": "data", "type": "[]byte"}]
                }
            }
        }
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               type_info=type_info, max_params=3)
        self.assertEqual(ann["params"][0].get("name"), "data")
        # Second param should have no name/type from type_info
        self.assertNotIn("name", ann["params"][1])

    def test_note_contains_version(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               go_version_hint="go1.21")
        self.assertIn("go1.21", ann["note"])

    def test_note_contains_register_names(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64")
        self.assertIn("RAX", ann["note"])

    def test_unsupported_arch_register_abi(self):
        ann = annotate_go_call("main.encrypt", "register", "sparc")
        self.assertIsNotNone(ann)
        self.assertEqual(ann["convention"], "register")
        self.assertIn("unsupported", ann["note"].lower())
        # No params/returns when architecture is unknown
        self.assertNotIn("params", ann)


class TestClosurePattern(unittest.TestCase):
    """Tests for Go closure function name pattern."""

    def test_simple_closure(self):
        self.assertIsNotNone(_CLOSURE_PATTERN.match("main.main.func1"))

    def test_init_closure(self):
        self.assertIsNotNone(_CLOSURE_PATTERN.match("main.init.func2"))

    def test_nested_closure(self):
        self.assertIsNotNone(_CLOSURE_PATTERN.match("pkg/sub.Handler.func1"))

    def test_not_closure(self):
        self.assertIsNone(_CLOSURE_PATTERN.match("main.main"))

    def test_not_closure_method(self):
        self.assertIsNone(_CLOSURE_PATTERN.match("main.(*T).Method"))


class TestEdgeCases(unittest.TestCase):
    """Edge cases and boundary conditions."""

    def test_detect_go_abi_whitespace_arch(self):
        self.assertEqual(detect_go_abi("go1.21", "  amd64  "), "register")

    def test_detect_go_abi_case_insensitive_arch(self):
        self.assertEqual(detect_go_abi("go1.21", "AMD64"), "register")

    def test_is_go_function_with_go_linkname(self):
        self.assertTrue(is_go_function("go:linkname_target"))

    def test_annotate_go_call_unknown_abi_type(self):
        """Unknown ABI type returns None."""
        ann = annotate_go_call("main.main", "unknown", "amd64")
        self.assertIsNone(ann)

    def test_type_info_not_dict(self):
        """Non-dict type_info is ignored gracefully."""
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               type_info="not a dict")
        self.assertIsNotNone(ann)
        # Should still work, just no type annotations
        self.assertNotIn("name", ann["params"][0])

    def test_type_info_empty_methods(self):
        ann = annotate_go_call("main.encrypt", "register", "amd64",
                               type_info={"methods": {}})
        self.assertIsNotNone(ann)


if __name__ == "__main__":
    unittest.main()
