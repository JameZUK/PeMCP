"""Tests for anti-VM bypass hooks module (_anti_vm_hooks.py).

Covers:
- Data accessor functions (registry keys, process names, MAC prefixes, firmware strings)
- check_anti_vm_triggers() summary logic
- _record_trigger() capping behaviour
- install functions exist as callables
- install_anti_vm_hooks returns proper structure with mock Qiling
"""
import unittest

from arkana.mcp._anti_vm_hooks import (
    MAX_BYPASS_TRIGGERS,
    _record_trigger,
    check_anti_vm_triggers,
    get_vm_firmware_strings,
    get_vm_mac_prefixes,
    get_vm_process_names,
    get_vm_registry_keys,
    install_anti_vm_hooks,
    install_cpuid_bypass,
    install_io_port_bypass,
    install_rdtsc_bypass,
)


class TestDataAccessors(unittest.TestCase):
    """Verify data accessor functions return correct types and known entries."""

    def test_registry_keys_type(self):
        result = get_vm_registry_keys()
        self.assertIsInstance(result, frozenset)

    def test_registry_keys_non_empty(self):
        result = get_vm_registry_keys()
        self.assertGreater(len(result), 0)

    def test_registry_keys_contains_vmware(self):
        keys = get_vm_registry_keys()
        vmware_keys = [k for k in keys if "VMware" in k or "vmware" in k.lower()]
        self.assertGreater(len(vmware_keys), 0, "Should contain VMware registry keys")

    def test_registry_keys_contains_virtualbox(self):
        keys = get_vm_registry_keys()
        vbox_keys = [k for k in keys if "VBox" in k or "VBOX" in k]
        self.assertGreater(len(vbox_keys), 0, "Should contain VirtualBox registry keys")

    def test_registry_keys_contains_hyperv(self):
        keys = get_vm_registry_keys()
        hyperv_keys = [k for k in keys if "vmbus" in k or "Virtual Machine" in k]
        self.assertGreater(len(hyperv_keys), 0, "Should contain Hyper-V registry keys")

    def test_registry_keys_contains_qemu(self):
        keys = get_vm_registry_keys()
        qemu_keys = [k for k in keys if "QEMU" in k]
        self.assertGreater(len(qemu_keys), 0, "Should contain QEMU registry keys")

    def test_process_names_type(self):
        result = get_vm_process_names()
        self.assertIsInstance(result, frozenset)

    def test_process_names_non_empty(self):
        result = get_vm_process_names()
        self.assertGreater(len(result), 0)

    def test_process_names_contains_vmware(self):
        names = get_vm_process_names()
        self.assertIn("vmtoolsd.exe", names)
        self.assertIn("vmwaretray.exe", names)

    def test_process_names_contains_virtualbox(self):
        names = get_vm_process_names()
        self.assertIn("vboxservice.exe", names)
        self.assertIn("vboxtray.exe", names)

    def test_process_names_contains_analysis_tools(self):
        names = get_vm_process_names()
        self.assertIn("wireshark.exe", names)
        self.assertIn("x64dbg.exe", names)
        self.assertIn("ollydbg.exe", names)

    def test_mac_prefixes_type(self):
        result = get_vm_mac_prefixes()
        self.assertIsInstance(result, frozenset)

    def test_mac_prefixes_non_empty(self):
        result = get_vm_mac_prefixes()
        self.assertGreater(len(result), 0)

    def test_mac_prefixes_contains_vmware(self):
        prefixes = get_vm_mac_prefixes()
        self.assertIn("00:0C:29", prefixes)
        self.assertIn("00:50:56", prefixes)

    def test_mac_prefixes_contains_virtualbox(self):
        prefixes = get_vm_mac_prefixes()
        self.assertIn("08:00:27", prefixes)

    def test_mac_prefixes_contains_qemu(self):
        prefixes = get_vm_mac_prefixes()
        self.assertIn("52:54:00", prefixes)

    def test_mac_prefixes_colon_format(self):
        """All MAC prefixes should use colon-separated format."""
        for prefix in get_vm_mac_prefixes():
            parts = prefix.split(":")
            self.assertEqual(len(parts), 3, f"Bad MAC format: {prefix}")
            for part in parts:
                self.assertEqual(len(part), 2, f"Bad MAC octet: {part} in {prefix}")

    def test_firmware_strings_type(self):
        result = get_vm_firmware_strings()
        self.assertIsInstance(result, frozenset)

    def test_firmware_strings_non_empty(self):
        result = get_vm_firmware_strings()
        self.assertGreater(len(result), 0)

    def test_firmware_strings_contains_vmware(self):
        strings = get_vm_firmware_strings()
        self.assertIn("VMware", strings)
        self.assertIn("VMware Virtual Platform", strings)

    def test_firmware_strings_contains_virtualbox(self):
        strings = get_vm_firmware_strings()
        self.assertIn("VirtualBox", strings)
        self.assertIn("VBOX", strings)

    def test_firmware_strings_contains_qemu(self):
        strings = get_vm_firmware_strings()
        self.assertIn("QEMU", strings)

    def test_firmware_strings_contains_kvm(self):
        strings = get_vm_firmware_strings()
        self.assertIn("KVMKVMKVM", strings)

    def test_firmware_strings_contains_hyperv(self):
        strings = get_vm_firmware_strings()
        self.assertIn("Microsoft Hv", strings)


class TestRecordTrigger(unittest.TestCase):
    """Test _record_trigger helper."""

    def test_appends_trigger(self):
        triggers = []
        _record_trigger(triggers, "cpuid", 0x401000, "test detail")
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0]["type"], "cpuid")
        self.assertEqual(triggers[0]["address"], 0x401000)
        self.assertEqual(triggers[0]["detail"], "test detail")

    def test_cap_at_max(self):
        """Trigger list should not grow beyond MAX_BYPASS_TRIGGERS."""
        triggers = [{"type": "x", "address": i, "detail": "d"} for i in range(MAX_BYPASS_TRIGGERS)]
        self.assertEqual(len(triggers), MAX_BYPASS_TRIGGERS)
        _record_trigger(triggers, "cpuid", 0xFFFF, "should be dropped")
        self.assertEqual(len(triggers), MAX_BYPASS_TRIGGERS)

    def test_appends_up_to_cap(self):
        triggers = [{"type": "x", "address": i, "detail": "d"} for i in range(MAX_BYPASS_TRIGGERS - 1)]
        _record_trigger(triggers, "cpuid", 0xAAAA, "last one")
        self.assertEqual(len(triggers), MAX_BYPASS_TRIGGERS)
        self.assertEqual(triggers[-1]["type"], "cpuid")


class TestCheckAntiVmTriggers(unittest.TestCase):
    """Test check_anti_vm_triggers summary generation."""

    def test_empty_triggers(self):
        result = check_anti_vm_triggers([])
        self.assertEqual(result["total_triggers"], 0)
        self.assertEqual(result["by_type"], {})
        self.assertEqual(result["unique_addresses"], 0)
        self.assertFalse(result["capped"])
        self.assertIn("No anti-VM bypass triggers", result["summary"])

    def test_single_trigger(self):
        triggers = [{"type": "cpuid", "address": 0x401000, "detail": "cleared bit"}]
        result = check_anti_vm_triggers(triggers)
        self.assertEqual(result["total_triggers"], 1)
        self.assertEqual(result["by_type"], {"cpuid": 1})
        self.assertEqual(result["unique_addresses"], 1)
        self.assertFalse(result["capped"])
        self.assertIn("1 anti-VM bypass triggered", result["summary"])

    def test_multiple_triggers_different_types(self):
        triggers = [
            {"type": "cpuid", "address": 0x401000, "detail": "a"},
            {"type": "rdtsc", "address": 0x401010, "detail": "b"},
            {"type": "rdtsc", "address": 0x401020, "detail": "c"},
            {"type": "io_port", "address": 0x401030, "detail": "d"},
        ]
        result = check_anti_vm_triggers(triggers)
        self.assertEqual(result["total_triggers"], 4)
        self.assertEqual(result["by_type"]["cpuid"], 1)
        self.assertEqual(result["by_type"]["rdtsc"], 2)
        self.assertEqual(result["by_type"]["io_port"], 1)
        self.assertEqual(result["unique_addresses"], 4)

    def test_duplicate_addresses(self):
        triggers = [
            {"type": "cpuid", "address": 0x401000, "detail": "a"},
            {"type": "cpuid", "address": 0x401000, "detail": "b"},
        ]
        result = check_anti_vm_triggers(triggers)
        self.assertEqual(result["total_triggers"], 2)
        self.assertEqual(result["unique_addresses"], 1)

    def test_capped_flag(self):
        triggers = [
            {"type": "cpuid", "address": i, "detail": f"d{i}"}
            for i in range(MAX_BYPASS_TRIGGERS)
        ]
        result = check_anti_vm_triggers(triggers)
        self.assertTrue(result["capped"])
        self.assertIn(str(MAX_BYPASS_TRIGGERS), result["summary"])

    def test_not_capped_when_under_limit(self):
        triggers = [
            {"type": "rdtsc", "address": i, "detail": f"d{i}"}
            for i in range(MAX_BYPASS_TRIGGERS - 1)
        ]
        result = check_anti_vm_triggers(triggers)
        self.assertFalse(result["capped"])

    def test_missing_address_in_trigger(self):
        """Triggers without an address should not crash."""
        triggers = [{"type": "cpuid", "detail": "no address"}]
        result = check_anti_vm_triggers(triggers)
        self.assertEqual(result["total_triggers"], 1)
        self.assertEqual(result["unique_addresses"], 0)

    def test_by_type_sorted_descending_in_summary(self):
        triggers = [
            {"type": "rdtsc", "address": 1, "detail": "a"},
            {"type": "rdtsc", "address": 2, "detail": "b"},
            {"type": "rdtsc", "address": 3, "detail": "c"},
            {"type": "cpuid", "address": 4, "detail": "d"},
        ]
        result = check_anti_vm_triggers(triggers)
        # rdtsc (3) should appear before cpuid (1) in the summary
        summary = result["summary"]
        rdtsc_pos = summary.index("rdtsc")
        cpuid_pos = summary.index("cpuid")
        self.assertLess(rdtsc_pos, cpuid_pos)


class TestInstallFunctions(unittest.TestCase):
    """Verify install functions exist, are callable, and handle failures gracefully."""

    def test_install_cpuid_bypass_is_callable(self):
        self.assertTrue(callable(install_cpuid_bypass))

    def test_install_rdtsc_bypass_is_callable(self):
        self.assertTrue(callable(install_rdtsc_bypass))

    def test_install_io_port_bypass_is_callable(self):
        self.assertTrue(callable(install_io_port_bypass))

    def test_install_cpuid_bypass_returns_false_on_bad_ql(self):
        """Passing a non-Qiling object should return False (not crash)."""
        result = install_cpuid_bypass(None, [])
        self.assertFalse(result)

    def test_install_rdtsc_bypass_returns_false_on_bad_ql(self):
        result = install_rdtsc_bypass(None, [])
        self.assertFalse(result)

    def test_install_io_port_bypass_returns_false_on_bad_ql(self):
        result = install_io_port_bypass(None, [])
        self.assertFalse(result)


class TestInstallAntiVmHooks(unittest.TestCase):
    """Test the master install_anti_vm_hooks function."""

    def test_returns_dict_with_expected_keys(self):
        """Even with None ql, should return a proper dict (all hooks fail)."""
        result = install_anti_vm_hooks(None)
        self.assertIn("installed", result)
        self.assertIn("failed", result)
        self.assertIn("triggers", result)
        self.assertIsInstance(result["installed"], list)
        self.assertIsInstance(result["failed"], list)
        self.assertIsInstance(result["triggers"], list)

    def test_all_hooks_fail_with_none_ql(self):
        result = install_anti_vm_hooks(None)
        self.assertEqual(len(result["installed"]), 0)
        self.assertEqual(len(result["failed"]), 3)
        self.assertIn("cpuid_bypass", result["failed"])
        self.assertIn("rdtsc_bypass", result["failed"])
        self.assertIn("io_port_bypass", result["failed"])

    def test_creates_trigger_list_if_none(self):
        result = install_anti_vm_hooks(None, triggers=None)
        self.assertIsInstance(result["triggers"], list)

    def test_uses_provided_trigger_list(self):
        my_triggers = [{"type": "existing", "address": 0, "detail": "pre-existing"}]
        result = install_anti_vm_hooks(None, triggers=my_triggers)
        self.assertIs(result["triggers"], my_triggers)

    def test_with_mock_ql_that_supports_hook_code(self):
        """A mock object with hook_code should report successful installs."""
        class MockQl:
            def hook_code(self, callback):
                pass
        result = install_anti_vm_hooks(MockQl())
        self.assertEqual(len(result["installed"]), 3)
        self.assertEqual(len(result["failed"]), 0)
        self.assertIn("cpuid_bypass", result["installed"])
        self.assertIn("rdtsc_bypass", result["installed"])
        self.assertIn("io_port_bypass", result["installed"])

    def test_with_mock_ql_that_raises_on_hook(self):
        """If hook_code raises, all hooks should be in the failed list."""
        class BrokenQl:
            def hook_code(self, callback):
                raise RuntimeError("hook not supported")
        result = install_anti_vm_hooks(BrokenQl())
        self.assertEqual(len(result["installed"]), 0)
        self.assertEqual(len(result["failed"]), 3)


class TestConstants(unittest.TestCase):
    """Verify module constants are sane."""

    def test_max_bypass_triggers_positive(self):
        self.assertGreater(MAX_BYPASS_TRIGGERS, 0)

    def test_max_bypass_triggers_is_10k(self):
        self.assertEqual(MAX_BYPASS_TRIGGERS, 10_000)


if __name__ == "__main__":
    unittest.main()
