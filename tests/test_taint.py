"""Tests for inter-procedural taint flow tracking (tools_taint.py)."""
import asyncio
import types
import unittest
from unittest.mock import MagicMock, patch

from arkana.state import AnalyzerState, _default_state


class TaintTaxonomyTests(unittest.TestCase):
    """Verify source/sink taxonomy completeness and consistency."""

    def test_source_categories_all_is_union(self):
        from arkana.mcp.tools_taint import (
            _SOURCE_CATEGORIES, _SOURCES_ALL,
            _SOURCES_NETWORK, _SOURCES_FILE, _SOURCES_USER_INPUT,
            _SOURCES_ENVIRONMENT, _SOURCES_REGISTRY,
        )
        union = _SOURCES_NETWORK | _SOURCES_FILE | _SOURCES_USER_INPUT | _SOURCES_ENVIRONMENT | _SOURCES_REGISTRY
        self.assertEqual(_SOURCES_ALL, union)
        self.assertEqual(_SOURCE_CATEGORIES["all"], _SOURCES_ALL)

    def test_sink_categories_all_is_union(self):
        from arkana.mcp.tools_taint import (
            _SINK_CATEGORIES, _SINKS_ALL,
            _SINKS_MEMORY, _SINKS_EXECUTION, _SINKS_FORMAT, _SINKS_EXFILTRATION,
        )
        union = _SINKS_MEMORY | _SINKS_EXECUTION | _SINKS_FORMAT | _SINKS_EXFILTRATION
        self.assertEqual(_SINKS_ALL, union)
        self.assertEqual(_SINK_CATEGORIES["all"], _SINKS_ALL)

    def test_all_sources_lowercase(self):
        from arkana.mcp.tools_taint import _SOURCES_ALL
        for api in _SOURCES_ALL:
            self.assertEqual(api, api.lower(), f"Source API not lowercase: {api}")

    def test_all_sinks_lowercase(self):
        from arkana.mcp.tools_taint import _SINKS_ALL
        for api in _SINKS_ALL:
            self.assertEqual(api, api.lower(), f"Sink API not lowercase: {api}")

    def test_source_categories_valid_keys(self):
        from arkana.mcp.tools_taint import _SOURCE_CATEGORIES
        expected = {"network", "file", "user_input", "environment", "registry", "all"}
        self.assertEqual(set(_SOURCE_CATEGORIES.keys()), expected)

    def test_sink_categories_valid_keys(self):
        from arkana.mcp.tools_taint import _SINK_CATEGORIES
        expected = {"memory", "execution", "format", "exfiltration", "all"}
        self.assertEqual(set(_SINK_CATEGORIES.keys()), expected)

    def test_risk_labels_cover_all_sinks(self):
        from arkana.mcp.tools_taint import _SINK_RISK_LABELS, _SINKS_ALL
        for api in _SINKS_ALL:
            self.assertIn(api, _SINK_RISK_LABELS,
                          f"Sink API {api} missing from _SINK_RISK_LABELS")

    def test_no_source_sink_overlap(self):
        """Sources and sinks should be disjoint (except gets which is both)."""
        from arkana.mcp.tools_taint import _SOURCES_ALL, _SINKS_ALL
        overlap = _SOURCES_ALL & _SINKS_ALL
        # 'gets' is legitimately both a source and a sink
        self.assertTrue(overlap <= {"gets", "gets_s"},
                        f"Unexpected source/sink overlap: {overlap - {'gets', 'gets_s'}}")


class ClassifyFunctionsTests(unittest.TestCase):
    """Test _classify_functions with mock CFG."""

    def _make_mock_cfg(self, functions_spec):
        """Build a mock CFG from a spec dict: {addr: (name, [callee_addrs], is_plt)}."""
        cfg = MagicMock()
        funcs = {}

        for addr, (name, callee_addrs, is_plt) in functions_spec.items():
            func_obj = MagicMock()
            func_obj.addr = addr
            func_obj.name = name
            func_obj.is_simprocedure = False
            func_obj.is_plt = is_plt

            # Build transition graph nodes
            nodes = [MagicMock(addr=addr)]  # self
            for ca in callee_addrs:
                nodes.append(MagicMock(addr=ca))
            func_obj.transition_graph.nodes.return_value = nodes
            funcs[addr] = func_obj

        cfg.functions = funcs
        return cfg

    def test_classify_finds_sources_and_sinks(self):
        from arkana.mcp.tools_taint import _classify_functions

        # Function at 0x1000 calls recv (0x9000)
        # Function at 0x2000 calls strcpy (0x9001)
        # 0x9000 is recv (PLT), 0x9001 is strcpy (PLT)
        cfg = self._make_mock_cfg({
            0x1000: ("handle_input", [0x9000], False),
            0x2000: ("copy_buffer", [0x9001], False),
            0x9000: ("recv", [], True),
            0x9001: ("strcpy", [], True),
        })

        sources = frozenset({"recv"})
        sinks = frozenset({"strcpy"})

        source_funcs, sink_funcs = _classify_functions(cfg, sources, sinks)

        self.assertIn(0x1000, source_funcs)
        self.assertEqual(source_funcs[0x1000], ["recv"])
        self.assertIn(0x2000, sink_funcs)
        self.assertEqual(sink_funcs[0x2000], ["strcpy"])
        # PLT functions should be excluded
        self.assertNotIn(0x9000, source_funcs)
        self.assertNotIn(0x9001, sink_funcs)

    def test_classify_excludes_simprocedures(self):
        from arkana.mcp.tools_taint import _classify_functions

        cfg = MagicMock()
        func = MagicMock()
        func.addr = 0x1000
        func.name = "recv_wrapper"
        func.is_simprocedure = True
        func.is_plt = False
        cfg.functions = {0x1000: func}

        source_funcs, sink_funcs = _classify_functions(
            cfg, frozenset({"recv"}), frozenset({"strcpy"}),
        )
        self.assertEqual(source_funcs, {})
        self.assertEqual(sink_funcs, {})

    def test_classify_function_both_source_and_sink(self):
        from arkana.mcp.tools_taint import _classify_functions

        # Function calls both recv and strcpy
        cfg = self._make_mock_cfg({
            0x1000: ("do_everything", [0x9000, 0x9001], False),
            0x9000: ("recv", [], True),
            0x9001: ("strcpy", [], True),
        })

        source_funcs, sink_funcs = _classify_functions(
            cfg, frozenset({"recv"}), frozenset({"strcpy"}),
        )
        self.assertIn(0x1000, source_funcs)
        self.assertIn(0x1000, sink_funcs)


class FindTaintChainsTests(unittest.TestCase):
    """Test BFS chain discovery."""

    def _make_callgraph(self, edges):
        """Build a mock callgraph (NetworkX-like) from edge list."""
        import collections
        adj = collections.defaultdict(set)
        pred = collections.defaultdict(set)
        nodes = set()
        for src, dst in edges:
            adj[src].add(dst)
            pred[dst].add(src)
            nodes.add(src)
            nodes.add(dst)

        graph = MagicMock()
        graph.successors = lambda n: list(adj.get(n, set()))
        graph.predecessors = lambda n: list(pred.get(n, set()))
        graph.__contains__ = lambda self, n: n in nodes
        return graph

    def _make_cfg_functions(self, names):
        """Build mock cfg.functions dict from {addr: name}."""
        funcs = {}
        for addr, name in names.items():
            func = MagicMock()
            func.name = name
            func.addr = addr
            funcs[addr] = func
        return funcs

    def test_direct_chain(self):
        from arkana.mcp.tools_taint import _find_taint_chains

        # 0x1000 (source) → 0x2000 (sink)
        callgraph = self._make_callgraph([(0x1000, 0x2000)])
        cfg_functions = self._make_cfg_functions({
            0x1000: "read_input",
            0x2000: "process",
        })
        source_funcs = {0x1000: ["recv"]}
        sink_funcs = {0x2000: ["strcpy"]}

        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=5, limit=10,
        )
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["depth"], 1)
        self.assertEqual(chains[0]["chain"], [hex(0x1000), hex(0x2000)])
        self.assertEqual(chains[0]["confidence"], "low")

    def test_two_hop_chain(self):
        from arkana.mcp.tools_taint import _find_taint_chains

        # 0x1000 (source) → 0x2000 → 0x3000 (sink)
        callgraph = self._make_callgraph([
            (0x1000, 0x2000),
            (0x2000, 0x3000),
        ])
        cfg_functions = self._make_cfg_functions({
            0x1000: "recv_data",
            0x2000: "transform",
            0x3000: "copy_buf",
        })
        source_funcs = {0x1000: ["recv"]}
        sink_funcs = {0x3000: ["memcpy"]}

        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=5, limit=10,
        )
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["depth"], 2)
        self.assertEqual(len(chains[0]["chain"]), 3)

    def test_max_depth_respected(self):
        from arkana.mcp.tools_taint import _find_taint_chains

        # Chain: 0x1 → 0x2 → 0x3 → 0x4 (sink)  depth=3
        callgraph = self._make_callgraph([
            (0x1, 0x2), (0x2, 0x3), (0x3, 0x4),
        ])
        cfg_functions = self._make_cfg_functions({
            0x1: "a", 0x2: "b", 0x3: "c", 0x4: "d",
        })
        source_funcs = {0x1: ["recv"]}
        sink_funcs = {0x4: ["strcpy"]}

        # max_depth=2 should not find it
        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=2, limit=10,
        )
        self.assertEqual(len(chains), 0)

        # max_depth=3 should find it
        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=3, limit=10,
        )
        self.assertEqual(len(chains), 1)

    def test_limit_respected(self):
        from arkana.mcp.tools_taint import _find_taint_chains

        # Multiple paths to sinks
        callgraph = self._make_callgraph([
            (0x1, 0x10), (0x1, 0x20), (0x1, 0x30),
        ])
        cfg_functions = self._make_cfg_functions({
            0x1: "src", 0x10: "s1", 0x20: "s2", 0x30: "s3",
        })
        source_funcs = {0x1: ["recv"]}
        sink_funcs = {0x10: ["strcpy"], 0x20: ["system"], 0x30: ["memcpy"]}

        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=5, limit=2,
        )
        self.assertEqual(len(chains), 2)

    def test_no_self_loop_chain(self):
        """A function that is both source and sink should not chain to itself."""
        from arkana.mcp.tools_taint import _find_taint_chains

        callgraph = self._make_callgraph([(0x1, 0x2)])
        cfg_functions = self._make_cfg_functions({0x1: "both", 0x2: "other"})
        source_funcs = {0x1: ["recv"]}
        sink_funcs = {0x1: ["strcpy"], 0x2: ["memcpy"]}

        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=5, limit=10,
        )
        # Should find 0x1 → 0x2 but NOT 0x1 → 0x1
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["sink_function"], hex(0x2))

    def test_reverse_mode_for_sink_target(self):
        from arkana.mcp.tools_taint import _find_taint_chains

        # 0x1 (source) → 0x2 → 0x3 (sink/target)
        callgraph = self._make_callgraph([
            (0x1, 0x2), (0x2, 0x3),
        ])
        cfg_functions = self._make_cfg_functions({
            0x1: "src_func", 0x2: "mid", 0x3: "sink_func",
        })
        source_funcs = {0x1: ["recv"]}
        sink_funcs = {0x3: ["strcpy"]}

        # Target is a sink → should trace backward
        chains = _find_taint_chains(
            callgraph, cfg_functions, source_funcs, sink_funcs,
            max_depth=5, limit=10, target_addr=0x3,
        )
        self.assertEqual(len(chains), 1)
        # Chain should be source → ... → sink (forward order)
        self.assertEqual(chains[0]["source_function"], hex(0x1))
        self.assertEqual(chains[0]["sink_function"], hex(0x3))


class DecompileValidationTests(unittest.TestCase):
    """Test Phase 2 decompile-based argument flow checking."""

    def test_check_argument_flow_positive(self):
        from arkana.mcp.tools_taint import _check_argument_flow

        lines = [
            "int handle_request(int sock) {",
            "    buf = recv(sock, buffer, 1024, 0);",
            "    process_data(buf, len);",
            "    return 0;",
            "}",
        ]
        result = _check_argument_flow(lines, ["recv"], "0x2000", "process_data")
        self.assertTrue(result)

    def test_check_argument_flow_negative(self):
        from arkana.mcp.tools_taint import _check_argument_flow

        lines = [
            "int handle_request(int sock) {",
            "    recv(sock, buffer, 1024, 0);",
            "    process_data(other_var, len);",
            "    return 0;",
            "}",
        ]
        # recv return not assigned to a variable
        result = _check_argument_flow(lines, ["recv"], "0x2000", "process_data")
        self.assertFalse(result)

    def test_check_parameter_to_sink_positive(self):
        from arkana.mcp.tools_taint import _check_parameter_to_sink

        lines = [
            "void copy_buffer(char *a0, int a1) {",
            "    strcpy(dest, a0);",
            "}",
        ]
        result = _check_parameter_to_sink(lines, ["strcpy"])
        self.assertTrue(result)

    def test_check_parameter_to_sink_negative(self):
        from arkana.mcp.tools_taint import _check_parameter_to_sink

        lines = [
            "void copy_buffer(char *a0, int a1) {",
            "    strcpy(dest, local_var);",
            "}",
        ]
        result = _check_parameter_to_sink(lines, ["strcpy"])
        self.assertFalse(result)


class SyncTraceFlowsTests(unittest.TestCase):
    """Test the orchestrator with mocked angr state."""

    def setUp(self):
        self._orig_pe_data = _default_state.pe_data
        self._orig_filepath = _default_state.filepath
        _default_state.pe_data = {"mode": "pe", "imports": []}
        _default_state.filepath = "/tmp/test.exe"

    def tearDown(self):
        _default_state.pe_data = self._orig_pe_data
        _default_state.filepath = self._orig_filepath

    def test_no_angr_returns_error(self):
        from arkana.mcp.tools_taint import _sync_trace_flows

        with patch("arkana.mcp.tools_taint.ANGR_AVAILABLE", False):
            result = _sync_trace_flows("all", "all", 5, True, False, None, 30)
        self.assertIn("error", result)

    def test_no_cfg_returns_error(self):
        from arkana.mcp.tools_taint import _sync_trace_flows

        with patch("arkana.mcp.tools_taint.state") as mock_state:
            mock_state.get_angr_snapshot.return_value = (MagicMock(), None)
            result = _sync_trace_flows("all", "all", 5, True, False, None, 30)
        self.assertIn("error", result)

    def test_invalid_source_category(self):
        from arkana.mcp.tools_taint import _sync_trace_flows

        with patch("arkana.mcp.tools_taint.ANGR_AVAILABLE", True), \
             patch("arkana.mcp.tools_taint.state") as mock_state:
            cfg = MagicMock()
            # MagicMock auto-creates .callgraph as an attribute
            mock_state.get_angr_snapshot.return_value = (MagicMock(), cfg)
            result = _sync_trace_flows("invalid_cat", "all", 5, True, False, None, 30)
        self.assertIn("error", result)
        self.assertIn("valid_categories", result)

    def test_invalid_sink_category(self):
        from arkana.mcp.tools_taint import _sync_trace_flows

        with patch("arkana.mcp.tools_taint.ANGR_AVAILABLE", True), \
             patch("arkana.mcp.tools_taint.state") as mock_state:
            cfg = MagicMock()
            mock_state.get_angr_snapshot.return_value = (MagicMock(), cfg)
            result = _sync_trace_flows("all", "bogus", 5, True, False, None, 30)
        self.assertIn("error", result)

    def test_no_sources_returns_empty(self):
        from arkana.mcp.tools_taint import _sync_trace_flows

        with patch("arkana.mcp.tools_taint.ANGR_AVAILABLE", True), \
             patch("arkana.mcp.tools_taint.state") as mock_state, \
             patch("arkana.mcp.tools_taint._classify_functions", return_value=({}, {0x2: ["strcpy"]})):
            cfg = MagicMock()
            cfg.functions = MagicMock()
            cfg.functions.callgraph = MagicMock()
            mock_state.get_angr_snapshot.return_value = (MagicMock(), cfg)
            result = _sync_trace_flows("all", "all", 5, True, False, None, 30)

        self.assertEqual(result["total_flows"], 0)
        self.assertEqual(result["source_functions_found"], 0)

    def test_end_to_end_with_mock_cfg(self):
        """Full orchestrator test with a small mock call graph."""
        from arkana.mcp.tools_taint import _sync_trace_flows
        import collections

        # Build mock CFG with 3 functions: source → middle → sink
        def _make_func(addr, name, callee_addrs, is_plt=False):
            f = MagicMock()
            f.addr = addr
            f.name = name
            f.is_simprocedure = False
            f.is_plt = is_plt
            nodes = [MagicMock(addr=addr)]
            for ca in callee_addrs:
                nodes.append(MagicMock(addr=ca))
            f.transition_graph.nodes.return_value = nodes
            return f

        funcs_dict = {
            0x1000: _make_func(0x1000, "handle_conn", [0x9000, 0x2000]),
            0x2000: _make_func(0x2000, "process", [0x3000]),
            0x3000: _make_func(0x3000, "copy_buf", [0x9001]),
            0x9000: _make_func(0x9000, "recv", [], is_plt=True),
            0x9001: _make_func(0x9001, "strcpy", [], is_plt=True),
        }

        # Mock callgraph
        adj = {0x1000: {0x9000, 0x2000}, 0x2000: {0x3000}, 0x3000: {0x9001}}
        pred = collections.defaultdict(set)
        for s, targets in adj.items():
            for t in targets:
                pred[t].add(s)

        callgraph = MagicMock()
        callgraph.successors = lambda n: list(adj.get(n, set()))
        callgraph.predecessors = lambda n: list(pred.get(n, set()))

        # Use a MagicMock for cfg.functions that behaves like a dict
        # but also has a .callgraph attribute
        funcs_mock = MagicMock()
        funcs_mock.__getitem__ = lambda self, k: funcs_dict[k]
        funcs_mock.__contains__ = lambda self, k: k in funcs_dict
        funcs_mock.__iter__ = lambda self: iter(funcs_dict)
        funcs_mock.items = lambda: funcs_dict.items()
        funcs_mock.keys = lambda: funcs_dict.keys()
        funcs_mock.get = lambda k, d=None: funcs_dict.get(k, d)
        funcs_mock.callgraph = callgraph

        cfg = MagicMock()
        cfg.functions = funcs_mock

        with patch("arkana.mcp.tools_taint.ANGR_AVAILABLE", True), \
             patch("arkana.mcp.tools_taint.state") as mock_state:
            mock_state.get_angr_snapshot.return_value = (MagicMock(), cfg)

            result = _sync_trace_flows("all", "all", 5, False, False, None, 30)

        self.assertGreaterEqual(result["total_flows"], 1)
        self.assertGreater(result["source_functions_found"], 0)
        self.assertGreater(result["sink_functions_found"], 0)

        # Verify chain structure
        chain = result["taint_flows"][0]
        self.assertIn("chain", chain)
        self.assertIn("source_apis", chain)
        self.assertIn("sink_apis", chain)
        self.assertIn("confidence", chain)
        self.assertIn("risk", chain)
        self.assertEqual(chain["confidence"], "low")  # No validation requested


class ConstantsTests(unittest.TestCase):
    """Verify taint constants are properly defined."""

    def test_constants_exist(self):
        from arkana.constants import (
            MAX_TAINT_CHAIN_DEPTH, MAX_TAINT_CHAINS,
            TAINT_RDA_PER_FUNC_TIMEOUT,
            TAINT_MAX_SOURCE_FUNCTIONS, TAINT_MAX_SINK_FUNCTIONS,
        )
        self.assertGreater(MAX_TAINT_CHAIN_DEPTH, 0)
        self.assertGreater(MAX_TAINT_CHAINS, 0)
        self.assertGreater(TAINT_RDA_PER_FUNC_TIMEOUT, 0)
        self.assertGreater(TAINT_MAX_SOURCE_FUNCTIONS, 0)
        self.assertGreater(TAINT_MAX_SINK_FUNCTIONS, 0)

    def test_depth_reasonable(self):
        from arkana.constants import MAX_TAINT_CHAIN_DEPTH
        self.assertLessEqual(MAX_TAINT_CHAIN_DEPTH, 50)

    def test_chains_reasonable(self):
        from arkana.constants import MAX_TAINT_CHAINS
        self.assertLessEqual(MAX_TAINT_CHAINS, 1000)


class ToolRegistrationTest(unittest.TestCase):
    """Verify the tool is importable and has the correct signature."""

    def test_tool_importable(self):
        from arkana.mcp.tools_taint import trace_taint_flows
        self.assertTrue(callable(trace_taint_flows))

    def test_module_imports_clean(self):
        """Module should import without side effects."""
        import importlib
        mod = importlib.import_module("arkana.mcp.tools_taint")
        self.assertTrue(hasattr(mod, "trace_taint_flows"))
        self.assertTrue(hasattr(mod, "_classify_functions"))
        self.assertTrue(hasattr(mod, "_find_taint_chains"))


if __name__ == "__main__":
    unittest.main()
