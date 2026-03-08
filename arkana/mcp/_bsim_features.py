"""BSim-inspired function feature extraction, similarity scoring, and SQLite DB management.

Extracts 6 feature groups from angr CFG/VEX IR for architecture-independent
function similarity matching.  No new heavy dependencies — uses angr (already
required for binary analysis tools), sqlite3 (stdlib), and math (stdlib).
"""

import datetime
import json
import math
import sqlite3
import threading
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from arkana.config import logger
from arkana.constants import BSIM_DB_DIR, BSIM_DEFAULT_THRESHOLD
from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB

# ---------------------------------------------------------------------------
#  Module-level lock for SQLite write serialisation
# ---------------------------------------------------------------------------
_db_write_lock = threading.Lock()

# ---------------------------------------------------------------------------
#  Feature weight configuration
# ---------------------------------------------------------------------------
FEATURE_WEIGHTS = {
    "cfg_structural": 0.20,
    "api_calls": 0.25,
    "vex_profile": 0.25,
    "string_refs": 0.15,
    "constants": 0.10,
    "size_metrics": 0.05,
}


# ===================================================================
#  1. Feature extraction
# ===================================================================

def _get_api_category(name: str) -> str:
    """Map an API/callee name to a semantic category."""
    entry = CATEGORIZED_IMPORTS_DB.get(name)
    if entry:
        return entry[1]  # (risk_level, category) -> category
    return "unknown"


def extract_function_features(
    project,
    cfg,
    func,
    *,
    include_vex: bool = False,
) -> Dict[str, Any]:
    """Extract a feature vector from a single angr Function object.

    Parameters
    ----------
    project : angr.Project
    cfg : angr.analyses.CFGFast
    func : angr.knowledge_plugins.functions.Function
    include_vex : bool
        Include VEX IR operation histogram (can be large).

    Returns
    -------
    dict with keys: address, name, cfg_structural, api_calls, vex_profile,
    string_refs, constants, size_metrics.
    """
    features: Dict[str, Any] = {
        "address": func.addr,
        "name": func.name or f"sub_{func.addr:x}",
    }

    # --- 1. CFG structural features ---
    blocks = list(func.blocks)
    block_count = len(blocks)
    graph = None
    try:
        graph = func.graph
        edge_count = graph.number_of_edges() if graph is not None else 0
    except Exception:
        edge_count = 0

    # Cyclomatic complexity: E - N + 2P (P=1 for single function)
    cyclomatic = edge_count - block_count + 2 if block_count > 0 else 0

    # Loop count via back-edge detection (iterative DFS — O(V+E), much
    # cheaper than nx.simple_cycles which uses Johnson's algorithm)
    loop_count = 0
    nesting_depth = 0
    try:
        if graph is not None and block_count > 1:
            visited: set = set()
            in_stack: set = set()
            for start in graph.nodes():
                if start in visited:
                    continue
                stack = [(start, iter(graph.successors(start)))]
                visited.add(start)
                in_stack.add(start)
                while stack:
                    node, children = stack[-1]
                    try:
                        child = next(children)
                        if child not in visited:
                            visited.add(child)
                            in_stack.add(child)
                            stack.append((child, iter(graph.successors(child))))
                        elif child in in_stack:
                            loop_count += 1
                    except StopIteration:
                        in_stack.discard(node)
                        stack.pop()
            nesting_depth = min(loop_count, 5)
    except Exception:
        pass

    features["cfg_structural"] = {
        "block_count": block_count,
        "edge_count": edge_count,
        "cyclomatic_complexity": cyclomatic,
        "loop_count": loop_count,
        "nesting_depth": nesting_depth,
    }

    # --- 2. API calls ---
    api_calls = []
    api_categories = set()

    # Walk callees via the function's transition graph
    try:
        if cfg is not None:
            node = cfg.model.get_any_node(func.addr)
            if node is not None:
                for succ in cfg.model.get_successors(node):
                    callee = cfg.functions.get(succ.addr)
                    if callee and callee.is_simprocedure:
                        api_calls.append(callee.name)
                        api_categories.add(_get_api_category(callee.name))

        # Also check direct function callees from the KB
        for callee_addr in func.functions_called():
            callee_func = cfg.functions.get(callee_addr) if cfg else None
            if callee_func:
                name = callee_func.name
                if name and name not in api_calls:
                    api_calls.append(name)
                    api_categories.add(_get_api_category(name))
    except Exception:
        pass

    api_calls.sort()
    features["api_calls"] = {
        "names": api_calls,
        "categories": sorted(api_categories - {"unknown"}),
        "count": len(api_calls),
    }

    # Pre-compute loaded object address ranges for fast constant filtering
    # (replaces per-constant project.loader.find_object_containing() calls)
    _addr_ranges: List[Tuple[int, int]] = []
    try:
        for obj in project.loader.all_objects:
            if hasattr(obj, 'min_addr') and hasattr(obj, 'max_addr'):
                _addr_ranges.append((obj.min_addr, obj.max_addr))
    except Exception:
        pass

    # --- Single-pass VEX IR extraction (features 3, 4, 5) ---
    # Lifts VEX once per block and extracts histogram, string refs, and
    # constants in a single traversal — previously 3 separate loops.
    vex_histogram: Dict[str, int] = {}
    string_hashes: List[int] = []
    constants: List[int] = []
    total_instructions = 0
    total_byte_size = 0

    for block in blocks:
        total_byte_size += block.size
        try:
            irsb = project.factory.block(block.addr, size=block.size).vex
            total_instructions += irsb.instructions
            for stmt in irsb.statements:
                tag = stmt.tag
                vex_histogram[tag] = vex_histogram.get(tag, 0) + 1
                for expr in stmt.expressions:
                    etag = expr.tag
                    vex_histogram[etag] = vex_histogram.get(etag, 0) + 1
                    # Extract constants for strings and magic numbers
                    if hasattr(expr, 'con') and hasattr(expr.con, 'value'):
                        val = expr.con.value
                        # Check if constant references a printable string
                        try:
                            s = project.loader.memory.load(val, 64)
                            decoded = s.split(b'\x00', 1)[0]
                            if len(decoded) >= 4 and all(0x20 <= b < 0x7f for b in decoded):
                                string_hashes.append(zlib.crc32(decoded) & 0xFFFFFFFF)
                        except Exception:
                            pass
                        # Collect interesting constants (exclude addresses)
                        if val > 0x1000 and not any(lo <= val <= hi for lo, hi in _addr_ranges):
                            constants.append(val)
        except Exception:
            continue

    if include_vex:
        features["vex_profile"] = {
            "histogram": vex_histogram,
            "total_ops": sum(vex_histogram.values()),
        }
    else:
        features["vex_profile"] = {
            "total_ops": sum(vex_histogram.values()),
        }

    # Store full histogram internally for scoring even when not in response
    features["_vex_histogram"] = vex_histogram

    features["string_refs"] = {
        "hashes": sorted(set(string_hashes)),
        "count": len(set(string_hashes)),
    }

    features["constants"] = {
        "values": sorted(set(constants)),
        "count": len(set(constants)),
    }

    # --- 6. Size metrics ---
    features["size_metrics"] = {
        "byte_size": total_byte_size,
        "instruction_count": total_instructions,
        "block_count": block_count,
    }

    return features


def is_trivial_function(func) -> bool:
    """Filter out functions that are too small to be meaningful for similarity."""
    try:
        blocks = list(func.blocks)
        if len(blocks) <= 1:
            return True
        if func.is_simprocedure or func.is_syscall:
            return True
        # Single-block thunks / PLT stubs
        if hasattr(func, 'is_plt') and func.is_plt:
            return True
    except Exception:
        return True
    return False


# ===================================================================
#  2. Similarity scoring
# ===================================================================

def _jaccard_similarity(set_a: set, set_b: set) -> float:
    """Jaccard index for two sets."""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def _cosine_similarity(hist_a: Dict[str, int], hist_b: Dict[str, int]) -> float:
    """Cosine similarity between two histograms (dicts of counts)."""
    if not hist_a and not hist_b:
        return 1.0
    if not hist_a or not hist_b:
        return 0.0

    all_keys = set(hist_a) | set(hist_b)
    dot = sum(hist_a.get(k, 0) * hist_b.get(k, 0) for k in all_keys)
    mag_a = math.sqrt(sum(v * v for v in hist_a.values()))
    mag_b = math.sqrt(sum(v * v for v in hist_b.values()))

    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _normalized_distance(values_a: Dict[str, float], values_b: Dict[str, float]) -> float:
    """Normalized distance similarity for scalar feature dicts.

    Returns a value in [0, 1] where 1.0 means identical.
    Uses normalized absolute difference: 1 - |a-b| / max(a, b, 1).
    """
    if not values_a and not values_b:
        return 1.0
    all_keys = set(values_a) | set(values_b)
    if not all_keys:
        return 1.0

    similarities = []
    for k in all_keys:
        a = values_a.get(k, 0)
        b = values_b.get(k, 0)
        max_val = max(abs(a), abs(b), 1)
        sim = 1.0 - abs(a - b) / max_val
        similarities.append(sim)

    return sum(similarities) / len(similarities)


def compute_similarity(
    features_a: Dict[str, Any],
    features_b: Dict[str, Any],
    metrics: str = "combined",
) -> Dict[str, float]:
    """Compute similarity between two feature vectors.

    Parameters
    ----------
    features_a, features_b : dict
        Feature vectors from extract_function_features().
    metrics : str
        "combined" (weighted sum), "cfg", "api", "vex", "strings",
        "constants", "size".

    Returns
    -------
    dict with per-group scores and combined score in [0.0, 1.0].
    """
    scores: Dict[str, float] = {}

    # 1. CFG structural
    cfg_a = features_a.get("cfg_structural", {})
    cfg_b = features_b.get("cfg_structural", {})
    scores["cfg_structural"] = _normalized_distance(
        {k: float(v) for k, v in cfg_a.items()},
        {k: float(v) for k, v in cfg_b.items()},
    )

    # 2. API calls
    api_a = set(features_a.get("api_calls", {}).get("names", []))
    api_b = set(features_b.get("api_calls", {}).get("names", []))
    scores["api_calls"] = _jaccard_similarity(api_a, api_b)

    # 3. VEX profile
    vex_a = features_a.get("_vex_histogram", features_a.get("vex_profile", {}).get("histogram", {}))
    vex_b = features_b.get("_vex_histogram", features_b.get("vex_profile", {}).get("histogram", {}))
    scores["vex_profile"] = _cosine_similarity(vex_a, vex_b)

    # 4. String references
    str_a = set(features_a.get("string_refs", {}).get("hashes", []))
    str_b = set(features_b.get("string_refs", {}).get("hashes", []))
    scores["string_refs"] = _jaccard_similarity(str_a, str_b)

    # 5. Constants
    const_a = set(features_a.get("constants", {}).get("values", []))
    const_b = set(features_b.get("constants", {}).get("values", []))
    scores["constants"] = _jaccard_similarity(const_a, const_b)

    # 6. Size metrics
    size_a = features_a.get("size_metrics", {})
    size_b = features_b.get("size_metrics", {})
    scores["size_metrics"] = _normalized_distance(
        {k: float(v) for k, v in size_a.items()},
        {k: float(v) for k, v in size_b.items()},
    )

    # Combined weighted score
    combined = sum(
        scores.get(group, 0.0) * weight
        for group, weight in FEATURE_WEIGHTS.items()
    )
    scores["combined"] = combined

    # If a single metric is requested, still return all scores but highlight it
    if metrics != "combined" and metrics in scores:
        scores["primary_metric"] = metrics
        scores["primary_score"] = scores[metrics]

    return scores


# ===================================================================
#  3. SQLite database management
# ===================================================================

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY,
    sha256 TEXT UNIQUE,
    filename TEXT,
    architecture TEXT,
    function_count INTEGER,
    indexed_at TEXT,
    file_size INTEGER
);

CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY,
    binary_id INTEGER REFERENCES binaries(id) ON DELETE CASCADE,
    address INTEGER,
    name TEXT,
    -- Numeric features for SQL pre-filtering
    block_count INTEGER,
    edge_count INTEGER,
    cyclomatic_complexity INTEGER,
    instruction_count INTEGER,
    byte_size INTEGER,
    loop_count INTEGER,
    -- Complex features as JSON blobs
    api_calls_json TEXT,
    string_hashes_json TEXT,
    constants_json TEXT,
    vex_op_histogram_json TEXT,
    cfg_structural_json TEXT,
    size_metrics_json TEXT,
    UNIQUE(binary_id, address)
);

CREATE INDEX IF NOT EXISTS idx_functions_structural
    ON functions(block_count, instruction_count);
"""


def _ensure_db_dir() -> Path:
    """Create the BSim DB directory if it doesn't exist."""
    BSIM_DB_DIR.mkdir(parents=True, exist_ok=True)
    return BSIM_DB_DIR


def get_db_path() -> Path:
    """Return the path to the signatures database."""
    return _ensure_db_dir() / "signatures.db"


def _get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open a WAL-mode connection to the signatures DB."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialise the schema (idempotent)."""
    conn = _get_connection(db_path)
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def _insert_function_row(conn, binary_id: int, feat: Dict[str, Any]) -> None:
    """Insert a single function feature row (no commit)."""
    cfg_s = feat.get("cfg_structural", {})
    size_s = feat.get("size_metrics", {})
    conn.execute(
        "INSERT OR REPLACE INTO functions "
        "(binary_id, address, name, block_count, edge_count, cyclomatic_complexity, "
        "instruction_count, byte_size, loop_count, api_calls_json, string_hashes_json, "
        "constants_json, vex_op_histogram_json, cfg_structural_json, size_metrics_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            binary_id,
            feat.get("address", 0),
            feat.get("name", ""),
            cfg_s.get("block_count", 0),
            cfg_s.get("edge_count", 0),
            cfg_s.get("cyclomatic_complexity", 0),
            size_s.get("instruction_count", 0),
            size_s.get("byte_size", 0),
            cfg_s.get("loop_count", 0),
            json.dumps(feat.get("api_calls", {})),
            json.dumps(feat.get("string_refs", {}).get("hashes", [])),
            json.dumps(feat.get("constants", {}).get("values", [])),
            json.dumps(feat.get("_vex_histogram", {})),
            json.dumps(cfg_s),
            json.dumps(size_s),
        ),
    )


def register_binary(
    sha256: str,
    filename: str,
    architecture: str,
    file_size: int,
    function_count: int = 0,
    db_path: Optional[Path] = None,
) -> Tuple[int, sqlite3.Connection]:
    """Register a binary in the DB and return (binary_id, open connection).

    The caller is responsible for committing and closing the connection.
    Must be called while holding ``_db_write_lock``.
    """
    conn = _get_connection(db_path)
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.execute("DELETE FROM binaries WHERE sha256 = ?", (sha256,))
        cursor = conn.execute(
            "INSERT INTO binaries (sha256, filename, architecture, function_count, indexed_at, file_size) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sha256, filename, architecture, function_count,
             datetime.datetime.now(datetime.timezone.utc).isoformat(), file_size),
        )
        return cursor.lastrowid, conn
    except BaseException:
        conn.close()
        raise


def store_functions_batch(
    conn,
    binary_id: int,
    features_batch: List[Dict[str, Any]],
) -> None:
    """Insert a batch of function features and commit (no lock — caller holds it)."""
    for feat in features_batch:
        _insert_function_row(conn, binary_id, feat)
    conn.commit()


def update_binary_function_count(
    conn,
    binary_id: int,
    count: int,
) -> None:
    """Update the function_count column after streaming inserts."""
    conn.execute(
        "UPDATE binaries SET function_count = ? WHERE id = ?",
        (count, binary_id),
    )
    conn.commit()


def store_binary_features(
    sha256: str,
    filename: str,
    architecture: str,
    file_size: int,
    features_list: List[Dict[str, Any]],
    db_path: Optional[Path] = None,
) -> int:
    """Store a binary and its function features into the DB.

    Returns the binary_id.  If the SHA256 already exists, the old
    entry is replaced (DELETE CASCADE removes old functions).
    """
    with _db_write_lock:
        binary_id, conn = register_binary(
            sha256, filename, architecture, file_size,
            function_count=len(features_list), db_path=db_path,
        )
        try:
            for feat in features_list:
                _insert_function_row(conn, binary_id, feat)
            conn.commit()
            return binary_id
        finally:
            conn.close()


def query_similar_functions(
    target_features: Dict[str, Any],
    threshold: float = BSIM_DEFAULT_THRESHOLD,
    metrics: str = "combined",
    limit: int = 10,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Two-phase query: SQL pre-filter then full similarity scoring.

    Phase 1: SQL filters candidates by block_count within 3x range.
    Phase 2: Full feature vector scoring on remaining candidates.
    """
    db = db_path or get_db_path()
    if not db.exists():
        return []

    conn = _get_connection(db)
    try:
        target_blocks = target_features.get("cfg_structural", {}).get("block_count", 0)
        # Pre-filter: block count within 3x range (eliminates ~80-90% of candidates)
        min_blocks = max(1, target_blocks // 3)
        max_blocks = max(target_blocks * 3, 3)

        cursor = conn.execute(
            "SELECT f.*, b.sha256, b.filename, b.architecture "
            "FROM functions f JOIN binaries b ON f.binary_id = b.id "
            "WHERE f.block_count BETWEEN ? AND ?",
            (min_blocks, max_blocks),
        )

        results = []
        for row in cursor:
            candidate = _row_to_features(row)
            scores = compute_similarity(target_features, candidate, metrics)
            score_key = metrics if metrics != "combined" else "combined"
            if scores.get(score_key, scores.get("combined", 0)) >= threshold:
                results.append({
                    "address": hex(row["address"]),
                    "name": row["name"],
                    "binary_sha256": row["sha256"],
                    "binary_filename": row["filename"],
                    "architecture": row["architecture"],
                    "scores": {k: round(v, 4) if isinstance(v, float) else v for k, v in scores.items()},
                })

        # Sort by combined score descending
        results.sort(key=lambda r: r["scores"].get("combined", 0), reverse=True)
        return results[:limit]
    finally:
        conn.close()


def list_indexed_binaries(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List all binaries in the signature DB with metadata."""
    db = db_path or get_db_path()
    if not db.exists():
        return []

    conn = _get_connection(db)
    try:
        rows = conn.execute(
            "SELECT sha256, filename, architecture, function_count, indexed_at, file_size "
            "FROM binaries ORDER BY indexed_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _row_to_features(row: sqlite3.Row) -> Dict[str, Any]:
    """Reconstruct a feature dict from a database row for scoring."""
    cfg_structural = json.loads(row["cfg_structural_json"]) if row["cfg_structural_json"] else {}
    size_metrics = json.loads(row["size_metrics_json"]) if row["size_metrics_json"] else {}
    api_calls = json.loads(row["api_calls_json"]) if row["api_calls_json"] else {}
    string_hashes = json.loads(row["string_hashes_json"]) if row["string_hashes_json"] else []
    constants = json.loads(row["constants_json"]) if row["constants_json"] else []
    vex_histogram = json.loads(row["vex_op_histogram_json"]) if row["vex_op_histogram_json"] else {}

    return {
        "address": row["address"],
        "name": row["name"],
        "cfg_structural": cfg_structural,
        "api_calls": api_calls if isinstance(api_calls, dict) else {"names": [], "categories": [], "count": 0},
        "string_refs": {"hashes": string_hashes, "count": len(string_hashes)},
        "constants": {"values": constants, "count": len(constants)},
        "_vex_histogram": vex_histogram,
        "size_metrics": size_metrics,
    }
