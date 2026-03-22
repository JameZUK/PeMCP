"""Unit tests for BSim function similarity features — scoring, normalization, SQLite."""

import json
import math
import tempfile
from pathlib import Path

import pytest

from arkana.mcp._bsim_features import (
    FEATURE_WEIGHTS,
    _cosine_similarity,
    _jaccard_similarity,
    _normalized_distance,
    _row_to_features,
    compute_similarity,
    get_db_path,
    init_db,
    list_indexed_binaries,
    query_similar_functions,
    store_binary_features,
)


# ---------------------------------------------------------------------------
#  Synthetic feature vector helpers
# ---------------------------------------------------------------------------

def _make_features(
    *,
    address=0x401000,
    block_count=5,
    edge_count=6,
    cyclomatic=3,
    loop_count=1,
    nesting_depth_approx=1,
    api_names=None,
    api_categories=None,
    vex_histogram=None,
    string_hashes=None,
    constants=None,
    byte_size=200,
    instruction_count=50,
):
    """Build a synthetic feature dict matching extract_function_features() output."""
    return {
        "address": address,
        "name": "test_func",
        "cfg_structural": {
            "block_count": block_count,
            "edge_count": edge_count,
            "cyclomatic_complexity": cyclomatic,
            "loop_count": loop_count,
            "nesting_depth_approx": nesting_depth_approx,
        },
        "api_calls": {
            "names": api_names or [],
            "categories": api_categories or [],
            "count": len(api_names) if api_names else 0,
        },
        "vex_profile": {
            "histogram": vex_histogram or {},
            "total_ops": sum((vex_histogram or {}).values()),
        },
        "_vex_histogram": vex_histogram or {},
        "string_refs": {
            "hashes": string_hashes or [],
            "count": len(string_hashes) if string_hashes else 0,
        },
        "constants": {
            "values": constants or [],
            "count": len(constants) if constants else 0,
        },
        "size_metrics": {
            "byte_size": byte_size,
            "instruction_count": instruction_count,
            "block_count": block_count,
        },
    }


# ===================================================================
#  Jaccard similarity tests
# ===================================================================

class TestJaccardSimilarity:

    def test_identical_sets(self):
        assert _jaccard_similarity({1, 2, 3}, {1, 2, 3}) == 1.0

    def test_disjoint_sets(self):
        assert _jaccard_similarity({1, 2}, {3, 4}) == 0.0

    def test_partial_overlap(self):
        # {1,2,3} & {2,3,4} = {2,3}; union = {1,2,3,4}
        assert _jaccard_similarity({1, 2, 3}, {2, 3, 4}) == pytest.approx(0.5)

    def test_empty_both(self):
        assert _jaccard_similarity(set(), set()) == 1.0

    def test_empty_one(self):
        assert _jaccard_similarity(set(), {1, 2}) == 0.0
        assert _jaccard_similarity({1, 2}, set()) == 0.0

    def test_single_element(self):
        assert _jaccard_similarity({1}, {1}) == 1.0
        assert _jaccard_similarity({1}, {2}) == 0.0


# ===================================================================
#  Cosine similarity tests
# ===================================================================

class TestCosineSimilarity:

    def test_identical_histograms(self):
        h = {"a": 3, "b": 4}
        assert _cosine_similarity(h, h) == pytest.approx(1.0)

    def test_orthogonal_histograms(self):
        assert _cosine_similarity({"a": 1}, {"b": 1}) == 0.0

    def test_proportional_histograms(self):
        # Same direction, different magnitude → cosine = 1.0
        assert _cosine_similarity({"a": 1, "b": 2}, {"a": 2, "b": 4}) == pytest.approx(1.0)

    def test_empty_both(self):
        assert _cosine_similarity({}, {}) == 1.0

    def test_empty_one(self):
        assert _cosine_similarity({}, {"a": 1}) == 0.0

    def test_partial_overlap(self):
        # a=1,b=0 vs a=0,b=1 → dot=0 → 0.0
        # a=1,b=1 vs a=1,b=0 → dot=1, mag_a=sqrt(2), mag_b=1 → 1/sqrt(2)
        result = _cosine_similarity({"a": 1, "b": 1}, {"a": 1})
        assert result == pytest.approx(1.0 / math.sqrt(2))


# ===================================================================
#  Normalized distance tests
# ===================================================================

class TestNormalizedDistance:

    def test_identical_values(self):
        v = {"x": 10.0, "y": 20.0}
        assert _normalized_distance(v, v) == pytest.approx(1.0)

    def test_completely_different(self):
        a = {"x": 100.0}
        b = {"x": 0.0}
        # 1 - |100-0|/max(100,0,1) = 1 - 100/100 = 0.0
        assert _normalized_distance(a, b) == pytest.approx(0.0)

    def test_partial_difference(self):
        a = {"x": 10.0}
        b = {"x": 5.0}
        # 1 - |10-5|/max(10,5,1) = 1 - 5/10 = 0.5
        assert _normalized_distance(a, b) == pytest.approx(0.5)

    def test_empty_both(self):
        assert _normalized_distance({}, {}) == 1.0

    def test_missing_keys(self):
        # a has "x"=10, b missing → b["x"]=0
        # 1 - |10-0|/max(10,0,1) = 1 - 10/10 = 0.0
        a = {"x": 10.0}
        b = {}
        assert _normalized_distance(a, b) == pytest.approx(0.0)

    def test_multiple_keys_averaged(self):
        a = {"x": 10.0, "y": 10.0}
        b = {"x": 10.0, "y": 0.0}
        # x: 1.0, y: 0.0 → average = 0.5
        assert _normalized_distance(a, b) == pytest.approx(0.5)


# ===================================================================
#  Combined similarity scoring tests
# ===================================================================

class TestComputeSimilarity:

    def test_identical_features(self):
        f = _make_features()
        scores = compute_similarity(f, f)
        assert scores["combined"] == pytest.approx(1.0)
        assert scores["cfg_structural"] == pytest.approx(1.0)
        assert scores["api_calls"] == pytest.approx(1.0)

    def test_completely_different_features(self):
        f1 = _make_features(
            block_count=100, edge_count=200, cyclomatic=50,
            api_names=["CreateRemoteThread", "WriteProcessMemory"],
            string_hashes=[111, 222],
            constants=[0x12345678],
            byte_size=5000, instruction_count=1000,
        )
        f2 = _make_features(
            block_count=2, edge_count=1, cyclomatic=1,
            api_names=["printf", "malloc"],
            string_hashes=[333, 444],
            constants=[0xDEADBEEF],
            byte_size=50, instruction_count=10,
        )
        scores = compute_similarity(f1, f2)
        assert scores["combined"] < 0.4
        assert scores["api_calls"] == 0.0
        assert scores["string_refs"] == 0.0
        assert scores["constants"] == 0.0

    def test_partial_api_overlap(self):
        f1 = _make_features(api_names=["CreateFile", "ReadFile", "CloseHandle"])
        f2 = _make_features(api_names=["CreateFile", "WriteFile", "CloseHandle"])
        scores = compute_similarity(f1, f2)
        # Jaccard: {CreateFile, CloseHandle} / {CreateFile, ReadFile, WriteFile, CloseHandle} = 2/4
        assert scores["api_calls"] == pytest.approx(0.5)

    def test_vex_similarity(self):
        vex1 = {"Ist_Put": 10, "Ist_Store": 5, "Iex_Const": 20}
        vex2 = {"Ist_Put": 10, "Ist_Store": 5, "Iex_Const": 20}
        f1 = _make_features(vex_histogram=vex1)
        f2 = _make_features(vex_histogram=vex2)
        scores = compute_similarity(f1, f2)
        assert scores["vex_profile"] == pytest.approx(1.0)

    def test_single_metric_mode(self):
        f = _make_features()
        scores = compute_similarity(f, f, metrics="api")
        assert "primary_metric" not in scores  # "api" not in scores keys
        scores = compute_similarity(f, f, metrics="api_calls")
        assert scores.get("primary_metric") == "api_calls"
        assert scores.get("primary_score") == pytest.approx(1.0)

    def test_single_metric_scores_roundable(self):
        """Scores dict with primary_metric (str) must survive round() in query results."""
        f = _make_features()
        scores = compute_similarity(f, f, metrics="api_calls")
        # This must not raise — primary_metric is a str, not a float
        rounded = {k: round(v, 4) if isinstance(v, float) else v for k, v in scores.items()}
        assert rounded["primary_metric"] == "api_calls"
        assert isinstance(rounded["combined"], float)

    def test_weights_sum_to_one(self):
        total = sum(FEATURE_WEIGHTS.values())
        assert total == pytest.approx(1.0)

    def test_empty_features(self):
        f1 = _make_features()
        f2 = _make_features()
        scores = compute_similarity(f1, f2)
        # All groups should score 1.0 for identical empty features
        assert scores["combined"] == pytest.approx(1.0)


# ===================================================================
#  SQLite database tests
# ===================================================================

class TestSQLiteOperations:

    def _tmp_db(self, tmp_path):
        db = tmp_path / "test_signatures.db"
        init_db(db)
        return db

    def test_init_db_creates_tables(self, tmp_path):
        db = self._tmp_db(tmp_path)
        assert db.exists()
        import sqlite3
        conn = sqlite3.connect(str(db))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        assert "binaries" in table_names
        assert "functions" in table_names
        conn.close()

    def test_init_db_idempotent(self, tmp_path):
        db = self._tmp_db(tmp_path)
        # Second call should not raise
        init_db(db)

    def test_store_and_list_binaries(self, tmp_path):
        db = self._tmp_db(tmp_path)
        features = [
            _make_features(address=0x401000),
            _make_features(address=0x402000, block_count=10, edge_count=15),
        ]
        binary_id = store_binary_features(
            sha256="abc123",
            filename="test.exe",
            architecture="x86_64",
            file_size=1024,
            features_list=features,
            db_path=db,
        )
        assert binary_id > 0

        binaries = list_indexed_binaries(db)
        assert len(binaries) == 1
        assert binaries[0]["sha256"] == "abc123"
        assert binaries[0]["function_count"] == 2

        # Verify both functions actually exist in the DB
        import sqlite3
        conn = sqlite3.connect(str(db))
        row_count = conn.execute(
            "SELECT COUNT(*) FROM functions WHERE binary_id = ?", (binary_id,)
        ).fetchone()[0]
        conn.close()
        assert row_count == 2

    def test_store_replaces_on_duplicate_sha256(self, tmp_path):
        db = self._tmp_db(tmp_path)
        f1 = [_make_features(address=0x401000)]
        f2 = [_make_features(address=0x401000), _make_features(address=0x402000, block_count=20)]

        store_binary_features("same_hash", "v1.exe", "x86", 100, f1, db)
        store_binary_features("same_hash", "v2.exe", "x86", 200, f2, db)

        binaries = list_indexed_binaries(db)
        assert len(binaries) == 1
        assert binaries[0]["filename"] == "v2.exe"
        assert binaries[0]["function_count"] == 2

    def test_query_empty_db(self, tmp_path):
        db = self._tmp_db(tmp_path)
        results = query_similar_functions(_make_features(), db_path=db)
        assert results == []

    def test_query_nonexistent_db(self, tmp_path):
        db = tmp_path / "nonexistent.db"
        results = query_similar_functions(_make_features(), db_path=db)
        assert results == []

    def test_query_finds_similar(self, tmp_path):
        db = self._tmp_db(tmp_path)
        target = _make_features(
            address=0x401000, block_count=5, edge_count=6, cyclomatic=3,
            api_names=["CreateFile", "ReadFile"],
            byte_size=200, instruction_count=50,
        )
        # Store a similar function
        similar = _make_features(
            address=0x501000, block_count=6, edge_count=7, cyclomatic=4,
            api_names=["CreateFile", "ReadFile"],
            byte_size=220, instruction_count=55,
        )
        store_binary_features("hash1", "similar.exe", "x86", 1000, [similar], db)

        results = query_similar_functions(target, threshold=0.5, db_path=db)
        assert len(results) >= 1
        assert results[0]["binary_sha256"] == "hash1"
        assert results[0]["scores"]["combined"] > 0.5

    def test_query_with_single_metric(self, tmp_path):
        """query_similar_functions must not crash when metrics != 'combined'."""
        db = self._tmp_db(tmp_path)
        target = _make_features(
            address=0x401000, block_count=5,
            api_names=["CreateFile", "ReadFile"],
        )
        similar = _make_features(
            address=0x501000, block_count=6,
            api_names=["CreateFile", "ReadFile"],
        )
        store_binary_features("hash_m", "metric.exe", "x86", 1000, [similar], db)

        results = query_similar_functions(
            target, threshold=0.3, metrics="api_calls", db_path=db,
        )
        assert len(results) >= 1
        # primary_metric should be a string, not crash round()
        assert results[0]["scores"]["primary_metric"] == "api_calls"
        assert isinstance(results[0]["scores"]["primary_score"], float)

    def test_query_respects_threshold(self, tmp_path):
        db = self._tmp_db(tmp_path)
        target = _make_features(block_count=5, api_names=["CreateFile"])
        dissimilar = _make_features(
            block_count=3, api_names=["printf", "malloc"],
            constants=[0xDEADBEEF], string_hashes=[999],
        )
        store_binary_features("hash2", "diff.exe", "x86", 500, [dissimilar], db)

        results = query_similar_functions(target, threshold=0.99, db_path=db)
        assert len(results) == 0

    def test_query_respects_limit(self, tmp_path):
        db = self._tmp_db(tmp_path)
        target = _make_features(block_count=5)
        # Store many similar functions with unique addresses
        funcs = [
            _make_features(address=0x401000 + i * 0x1000, block_count=5 + i % 3)
            for i in range(20)
        ]
        store_binary_features("hash3", "many.exe", "x86", 2000, funcs, db)

        results = query_similar_functions(target, threshold=0.0, limit=5, db_path=db)
        assert len(results) == 5

    def test_query_pre_filter_excludes_distant(self, tmp_path):
        db = self._tmp_db(tmp_path)
        # Target has 5 blocks, candidate has 50 (>3x ratio)
        target = _make_features(block_count=5)
        distant = _make_features(block_count=50)
        store_binary_features("hash4", "distant.exe", "x86", 500, [distant], db)

        results = query_similar_functions(target, threshold=0.0, db_path=db)
        # 50 > 5*3=15, so the pre-filter should exclude it
        assert len(results) == 0


# ===================================================================
#  Row-to-features reconstruction tests
# ===================================================================

class TestRowToFeatures:

    def test_reconstructs_all_fields(self):
        """Verify _row_to_features correctly reconstructs from a mock row."""
        import sqlite3
        # Create a minimal in-memory DB with the row
        conn = sqlite3.connect(":memory:")
        conn.execute("""
            CREATE TABLE test (
                address INTEGER, name TEXT,
                block_count INTEGER, edge_count INTEGER,
                cyclomatic_complexity INTEGER, instruction_count INTEGER,
                byte_size INTEGER, loop_count INTEGER,
                api_calls_json TEXT, string_hashes_json TEXT,
                constants_json TEXT, vex_op_histogram_json TEXT,
                cfg_structural_json TEXT, size_metrics_json TEXT
            )
        """)
        conn.execute(
            "INSERT INTO test VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                0x401000, "test_func", 5, 6, 3, 50, 200, 1,
                json.dumps({"names": ["ReadFile"], "categories": ["file_io"], "count": 1}),
                json.dumps([12345]),
                json.dumps([0x5678]),
                json.dumps({"Ist_Put": 10}),
                json.dumps({"block_count": 5, "edge_count": 6}),
                json.dumps({"byte_size": 200, "instruction_count": 50}),
            ),
        )
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM test").fetchone()

        features = _row_to_features(row)
        assert features["address"] == 0x401000
        assert features["name"] == "test_func"
        assert features["cfg_structural"]["block_count"] == 5
        assert features["api_calls"]["names"] == ["ReadFile"]
        assert features["string_refs"]["hashes"] == [12345]
        assert features["constants"]["values"] == [0x5678]
        assert features["_vex_histogram"] == {"Ist_Put": 10}
        conn.close()


# ===================================================================
#  Serialization round-trip tests
# ===================================================================

class TestSerializationRoundTrip:

    def test_features_json_roundtrip(self):
        """Features should survive JSON serialization."""
        original = _make_features(
            api_names=["CreateFile", "ReadFile"],
            vex_histogram={"Ist_Put": 10, "Ist_Store": 5},
            string_hashes=[111, 222, 333],
            constants=[0xDEAD, 0xBEEF],
        )
        serialized = json.dumps(original)
        restored = json.loads(serialized)
        scores = compute_similarity(original, restored)
        assert scores["combined"] == pytest.approx(1.0)

    def test_store_and_query_roundtrip(self, tmp_path):
        """Store features → query back → scores should be high."""
        db = tmp_path / "roundtrip.db"
        init_db(db)
        original = _make_features(
            block_count=8, edge_count=10, cyclomatic=4,
            api_names=["InternetOpen", "HttpSendRequest"],
            vex_histogram={"Ist_Put": 20, "Iex_Const": 15},
            string_hashes=[1111, 2222],
            constants=[0xCAFE],
            byte_size=500, instruction_count=120,
        )
        store_binary_features("hash_rt", "roundtrip.exe", "x86", 2000, [original], db)
        results = query_similar_functions(original, threshold=0.0, db_path=db)
        assert len(results) >= 1
        # Should match with high score (VEX histogram stored separately)
        assert results[0]["scores"]["combined"] > 0.7
