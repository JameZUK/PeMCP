"""BSim-inspired function feature extraction, similarity scoring, and SQLite DB management.

Extracts 6 feature groups from angr CFG/VEX IR for architecture-independent
function similarity matching.  No new heavy dependencies — uses angr (already
required for binary analysis tools), sqlite3 (stdlib), and math (stdlib).

Confidence scoring uses TF-IDF-style weighting: shared rare features (e.g.
a specific crypto API) contribute more than common ones (e.g. malloc).
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
from arkana.constants import BSIM_DB_DIR, BSIM_DEFAULT_THRESHOLD, BSIM_MIN_BLOCKS_FOR_MATCH
from arkana.mcp._category_maps import CATEGORIZED_IMPORTS_DB

# ---------------------------------------------------------------------------
#  Module-level lock for SQLite write serialisation
# ---------------------------------------------------------------------------
_db_write_lock = threading.Lock()

# ---------------------------------------------------------------------------
#  Feature weight configuration
# ---------------------------------------------------------------------------
FEATURE_WEIGHTS = {
    "cfg_structural": 0.15,
    "api_calls": 0.20,
    "vex_profile": 0.10,      # Reduced — research shows histograms are low-discriminative
    "string_refs": 0.15,
    "constants": 0.10,
    "size_metrics": 0.05,
    "block_hashes": 0.15,     # New — mnemonic sequences per block, much more discriminative
    "call_context": 0.10,     # New — imported API caller/callee context
}

# angr pseudo-APIs that appear whenever indirect calls/jumps can't be resolved.
# These pollute similarity scoring, confidence calculation, and API overlap
# checks — two completely unrelated functions both calling through a vtable
# will both show "UnresolvableCallTarget" as a shared API, producing false
# positive matches.  Filtered from all API-based comparisons.
ANGR_PSEUDO_APIS = frozenset({
    "UnresolvableCallTarget",
    "UnresolvableJumpTarget",
    "PathTerminator",
    "ReturnUnconstrained",
    "Unconstrained",
    "SimProcedure",
})


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
        "nesting_depth_approx": nesting_depth,  # Approximated as capped loop count
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

        # Also check direct function callees from the KB.
        # Filter out internal sub_* names — they're meaningless for cross-binary
        # matching and dilute the Jaccard similarity score.
        for callee_addr in func.functions_called():
            callee_func = cfg.functions.get(callee_addr) if cfg else None
            if callee_func:
                name = callee_func.name
                if (name
                        and name not in api_calls
                        and not name.startswith("sub_")
                        and name not in ANGR_PSEUDO_APIS):
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

    # --- Single-pass VEX IR + block hash extraction (features 3, 4, 5, 7) ---
    # Lifts VEX once per block and extracts histogram, string refs, constants,
    # and block mnemonic hashes in a single traversal.
    vex_histogram: Dict[str, int] = {}
    string_hashes: List[int] = []
    constants: List[int] = []
    block_hashes: List[int] = []
    total_instructions = 0
    total_byte_size = 0

    for block in blocks:
        total_byte_size += block.size
        try:
            blk = project.factory.block(block.addr, size=block.size)

            # Block hash: CRC32 of ordered mnemonic sequence (no operands).
            # Two blocks with the same instruction types in the same order
            # produce the same hash regardless of register allocation or
            # constant values — more discriminative than VEX histogram.
            try:
                mnemonics = [insn.mnemonic for insn in blk.capstone.insns]
                if mnemonics:
                    mnem_str = ",".join(mnemonics)
                    block_hashes.append(zlib.crc32(mnem_str.encode()) & 0xFFFFFFFF)
            except Exception:
                pass

            irsb = blk.vex
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
                        # Pre-check address ranges before attempting memory load
                        in_range = any(lo <= val <= hi for lo, hi in _addr_ranges)
                        # Check if constant references a printable string
                        if in_range:
                            try:
                                s = project.loader.memory.load(val, 64)
                                decoded = s.split(b'\x00', 1)[0]
                                if len(decoded) >= 4 and all(0x20 <= b < 0x7f for b in decoded):
                                    string_hashes.append(zlib.crc32(decoded) & 0xFFFFFFFF)
                            except Exception:
                                pass
                        # Collect interesting constants (exclude addresses)
                        if val > 0x1000 and not in_range:
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

    # --- 7. Block hashes (mnemonic sequences per basic block) ---
    features["block_hashes"] = {
        "hashes": sorted(set(block_hashes)),
        "count": len(set(block_hashes)),
    }

    # --- 8. Call context (imported API callees/callers) ---
    import_callees: set = set()
    import_callers: set = set()
    try:
        # Callees: which imported APIs does this function call?
        for callee_addr in func.functions_called():
            callee_func = cfg.functions.get(callee_addr) if cfg else None
            if callee_func and callee_func.is_simprocedure:
                cname = callee_func.name
                if cname and cname not in ANGR_PSEUDO_APIS:
                    import_callees.add(cname)
        # Callers: which imported APIs are among this function's callers?
        if cfg is not None:
            for caller_addr in cfg.functions.callgraph.predecessors(func.addr):
                caller_func = cfg.functions.get(caller_addr)
                if caller_func and caller_func.is_simprocedure:
                    cname = caller_func.name
                    if cname and cname not in ANGR_PSEUDO_APIS:
                        import_callers.add(cname)
    except Exception:
        pass

    features["call_context"] = {
        "import_callees": sorted(import_callees),
        "import_callers": sorted(import_callers),
        "callee_count": len(import_callees),
        "caller_count": len(import_callers),
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

    # 2. API calls (exclude angr pseudo-APIs that pollute similarity)
    api_a = set(features_a.get("api_calls", {}).get("names", [])) - ANGR_PSEUDO_APIS
    api_b = set(features_b.get("api_calls", {}).get("names", [])) - ANGR_PSEUDO_APIS
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

    # 7. Block hashes (mnemonic sequence hashes per basic block)
    bh_a = set(features_a.get("block_hashes", {}).get("hashes", []))
    bh_b = set(features_b.get("block_hashes", {}).get("hashes", []))
    scores["block_hashes"] = _jaccard_similarity(bh_a, bh_b)

    # 8. Call context (imported API callees/callers)
    cc_a = set(features_a.get("call_context", {}).get("import_callees", []))
    cc_b = set(features_b.get("call_context", {}).get("import_callees", []))
    scores["call_context"] = _jaccard_similarity(cc_a, cc_b)

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
#  2b. Confidence scoring (TF-IDF-style significance)
# ===================================================================

def compute_feature_idf(db_path: Optional[Path] = None) -> Dict[str, float]:
    """Compute inverse document frequency for API calls across the DB.

    Returns a dict mapping API name → IDF weight.  Rare APIs get higher
    weights.  Used by ``compute_confidence()`` to distinguish meaningful
    matches from trivial ones.

    IDF = log(N / (1 + df))  where N = total functions, df = functions containing this API.
    """
    db = db_path or get_db_path()
    if not db.exists():
        return {}

    conn = _get_connection(db)
    try:
        total_row = conn.execute("SELECT COUNT(*) FROM functions").fetchone()
        total_functions = total_row[0] if total_row else 0
        if total_functions == 0:
            return {}

        # Count document frequency per API name
        api_df: Dict[str, int] = {}
        rows = conn.execute("SELECT api_calls_json FROM functions").fetchall()
        for row in rows:
            api_data = _safe_json_loads(row[0], {})
            names = api_data.get("names", []) if isinstance(api_data, dict) else []
            for name in set(names):  # deduplicate per-function
                api_df[name] = api_df.get(name, 0) + 1

        # Compute IDF
        idf: Dict[str, float] = {}
        for name, df in api_df.items():
            idf[name] = math.log(total_functions / (1 + df))

        return idf
    finally:
        conn.close()


def compute_confidence(
    features_a: Dict[str, Any],
    features_b: Dict[str, Any],
    similarity_scores: Dict[str, float],
    idf_weights: Optional[Dict[str, float]] = None,
) -> float:
    """Compute a confidence/significance score for a similarity match.

    Higher confidence means the match is more meaningful — shared rare
    features contribute more than common ones.  A trivial ``return 0``
    function may have similarity=1.0 but near-zero confidence.

    Components:
    1. **Shared API significance**: Sum of IDF weights for shared API calls
    2. **Feature richness**: How many non-empty feature groups both functions have
    3. **Size factor**: Larger functions are more significant matches
    4. **Similarity boost**: Weighted by the combined similarity score

    Returns a float ≥ 0.  Typical range: 0-50 for meaningful matches.
    """
    confidence = 0.0

    # 1. Shared API significance (IDF-weighted)
    # Filter out angr pseudo-APIs that inflate confidence without meaning
    api_a = set(features_a.get("api_calls", {}).get("names", [])) - ANGR_PSEUDO_APIS
    api_b = set(features_b.get("api_calls", {}).get("names", [])) - ANGR_PSEUDO_APIS
    shared_apis = api_a & api_b
    if idf_weights and shared_apis:
        # Default IDF of 1.0 for APIs not in the DB (novel = significant)
        api_significance = sum(idf_weights.get(name, 1.0) for name in shared_apis)
        confidence += api_significance
    elif shared_apis:
        # No IDF available — use count as rough proxy
        confidence += len(shared_apis) * 0.5

    # 2. Feature richness (0-6 points)
    richness = 0
    for key in ("api_calls", "string_refs", "constants"):
        a_items = features_a.get(key, {})
        b_items = features_b.get(key, {})
        a_count = a_items.get("count", 0) if isinstance(a_items, dict) else 0
        b_count = b_items.get("count", 0) if isinstance(b_items, dict) else 0
        if a_count > 0 and b_count > 0:
            richness += 1
    # VEX and CFG are almost always present
    a_blocks = features_a.get("cfg_structural", {}).get("block_count", 0)
    b_blocks = features_b.get("cfg_structural", {}).get("block_count", 0)
    if a_blocks > BSIM_MIN_BLOCKS_FOR_MATCH and b_blocks > BSIM_MIN_BLOCKS_FOR_MATCH:
        richness += 1
    confidence += richness

    # 3. Size factor — larger functions are more significant
    a_instr = features_a.get("size_metrics", {}).get("instruction_count", 0)
    b_instr = features_b.get("size_metrics", {}).get("instruction_count", 0)
    min_instr = min(a_instr, b_instr)
    # Log scale: 10 instr → 1.0, 100 → 2.0, 1000 → 3.0
    if min_instr > 0:
        confidence += math.log10(max(min_instr, 1))

    # 4. Multiply by similarity to penalize low-similarity matches
    combined_sim = similarity_scores.get("combined", 0.0)
    confidence *= max(combined_sim, 0.01)  # Avoid zeroing out entirely

    return round(confidence, 2)


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
    file_size INTEGER,
    source TEXT DEFAULT 'user',
    library_name TEXT
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
    block_hashes_json TEXT,
    call_context_json TEXT,
    UNIQUE(binary_id, address)
);

CREATE INDEX IF NOT EXISTS idx_functions_structural
    ON functions(block_count, instruction_count);

CREATE INDEX IF NOT EXISTS idx_functions_arch
    ON binaries(architecture);

CREATE INDEX IF NOT EXISTS idx_binaries_source
    ON binaries(source);
"""


def _ensure_db_dir() -> Path:
    """Create the BSim DB directory if it doesn't exist."""
    BSIM_DB_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)  # M3-v10
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
    """Initialise the schema (idempotent).

    Uses CREATE TABLE/INDEX IF NOT EXISTS, so safe to call on existing DBs.
    """
    conn = _get_connection(db_path)
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def _safe_json_dumps(obj, fallback="{}"):
    """Serialize *obj* to JSON, returning *fallback* on encoding errors."""
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        logger.warning("Failed to JSON-encode BSim feature, using fallback")
        return fallback


def _insert_function_row(conn, binary_id: int, feat: Dict[str, Any]) -> None:
    """Insert a single function feature row (no commit)."""
    cfg_s = feat.get("cfg_structural", {})
    size_s = feat.get("size_metrics", {})
    conn.execute(
        "INSERT OR REPLACE INTO functions "
        "(binary_id, address, name, block_count, edge_count, cyclomatic_complexity, "
        "instruction_count, byte_size, loop_count, api_calls_json, string_hashes_json, "
        "constants_json, vex_op_histogram_json, cfg_structural_json, size_metrics_json, "
        "block_hashes_json, call_context_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            _safe_json_dumps(feat.get("api_calls", {})),
            _safe_json_dumps(feat.get("string_refs", {}).get("hashes", []), "[]"),
            _safe_json_dumps(feat.get("constants", {}).get("values", []), "[]"),
            _safe_json_dumps(feat.get("_vex_histogram", {})),
            _safe_json_dumps(cfg_s),
            _safe_json_dumps(size_s),
            _safe_json_dumps(feat.get("block_hashes", {}).get("hashes", []), "[]"),
            _safe_json_dumps(feat.get("call_context", {})),
        ),
    )


def register_binary(
    sha256: str,
    filename: str,
    architecture: str,
    file_size: int,
    function_count: int = 0,
    db_path: Optional[Path] = None,
    source: str = "user",
    library_name: Optional[str] = None,
) -> Tuple[int, sqlite3.Connection]:
    """Register a binary in the DB and return (binary_id, open connection).

    The caller is responsible for committing and closing the connection.
    Must be called while holding ``_db_write_lock``.

    Parameters
    ----------
    source : str
        'user' for analyst-indexed binaries, 'library' for starter DB entries.
    library_name : str, optional
        Human-readable library name (e.g. 'OpenSSL 1.1.1').
    """
    conn = _get_connection(db_path)
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.execute("DELETE FROM binaries WHERE sha256 = ?", (sha256,))
        cursor = conn.execute(
            "INSERT INTO binaries (sha256, filename, architecture, function_count, "
            "indexed_at, file_size, source, library_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sha256, filename, architecture, function_count,
             datetime.datetime.now(datetime.timezone.utc).isoformat(), file_size,
             source, library_name),
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
    source_architecture: Optional[str] = None,
    min_blocks: int = BSIM_MIN_BLOCKS_FOR_MATCH,
    idf_weights: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Two-phase query: SQL pre-filter then full similarity + confidence scoring.

    Phase 1: SQL filters candidates by block_count and instruction_count
             within 3x range, plus optional architecture exact match.
    Phase 2: Full feature vector scoring + confidence on remaining candidates.

    Results are sorted by ``confidence * similarity`` (significance) by default.

    Parameters
    ----------
    target_features : dict
        Feature vector from extract_function_features().
    threshold : float
        Minimum similarity score (0.0-1.0).
    metrics : str
        Scoring metric for primary ranking.
    limit : int
        Maximum results to return.
    db_path : Path, optional
        Override signature DB path.
    source_architecture : str, optional
        Architecture filter (e.g. 'AMD64', 'X86').
    min_blocks : int
        Suppress trivial matches below this block count (default 3).
    idf_weights : dict, optional
        Pre-computed IDF weights from compute_feature_idf().  If None,
        confidence is computed without IDF weighting.
    """
    db = db_path or get_db_path()
    if not db.exists():
        return []

    conn = _get_connection(db)
    try:
        target_blocks = target_features.get("cfg_structural", {}).get("block_count", 0)
        target_instruction_count = target_features.get("size_metrics", {}).get("instruction_count", 0)

        # Build dynamic pre-filter query
        block_lo = max(min_blocks, target_blocks // 3)
        block_hi = max(target_blocks * 3, min_blocks)
        conditions: List[str] = ["f.block_count BETWEEN ? AND ?"]
        params: List[Any] = [block_lo, block_hi]

        # Instruction count filter (skip if unknown/zero)
        if target_instruction_count > 0:
            instr_min = max(1, target_instruction_count // 3)
            instr_max = target_instruction_count * 3
            conditions.append("f.instruction_count BETWEEN ? AND ?")
            params.extend([instr_min, instr_max])

        # Architecture filter (skip if unknown/empty)
        if source_architecture:
            conditions.append("b.architecture = ?")
            params.append(source_architecture)

        where_clause = " AND ".join(conditions)
        query = (
            "SELECT f.*, b.sha256, b.filename, b.architecture, "
            "b.source, b.library_name "
            "FROM functions f JOIN binaries b ON f.binary_id = b.id "
            f"WHERE {where_clause} "
            "LIMIT 10000"
        )

        cursor = conn.execute(query, params)

        results = []
        candidate_count = 0
        for row in cursor:
            candidate_count += 1
            candidate = _row_to_features(row)
            scores = compute_similarity(target_features, candidate, metrics)
            score_key = metrics if metrics in scores else "combined"
            sim_score = scores.get(score_key, scores.get("combined", 0))
            if sim_score >= threshold:
                confidence = compute_confidence(
                    target_features, candidate, scores, idf_weights
                )
                result_entry = {
                    "address": hex(row["address"]),
                    "name": row["name"],
                    "binary_sha256": row["sha256"],
                    "binary_filename": row["filename"],
                    "architecture": row["architecture"],
                    "scores": {k: round(v, 4) if isinstance(v, float) else v for k, v in scores.items()},
                    "confidence": confidence,
                }
                # Include source info if available
                try:
                    if row["source"]:
                        result_entry["source"] = row["source"]
                    if row["library_name"]:
                        result_entry["library_name"] = row["library_name"]
                except (IndexError, KeyError):
                    pass
                results.append(result_entry)

        logger.debug(
            "BSim pre-filter: %d candidates (blocks=%d-%d, instr=%s, arch=%s)",
            candidate_count, block_lo, block_hi,
            f"{max(1, target_instruction_count // 3)}-{target_instruction_count * 3}"
            if target_instruction_count > 0 else "any",
            source_architecture or "any",
        )

        # Sort by significance (confidence × similarity) descending
        results.sort(
            key=lambda r: r.get("confidence", 0) * r["scores"].get("combined", 0),
            reverse=True,
        )
        return results[:limit]
    finally:
        conn.close()


def is_binary_indexed(sha256: str, db_path: Optional[Path] = None) -> bool:
    """Check if a binary with the given SHA256 is already in the signature DB."""
    db = db_path or get_db_path()
    if not db.exists():
        return False
    conn = _get_connection(db)
    try:
        row = conn.execute(
            "SELECT 1 FROM binaries WHERE sha256 = ? LIMIT 1", (sha256,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def update_function_name(
    sha256: str,
    address: int,
    new_name: str,
    db_path: Optional[Path] = None,
) -> bool:
    """Update a function's name in the BSim DB.

    Called when the user renames a function so the name is available for
    ``transfer_annotations`` to carry over to variants.  No-op if the
    binary is not indexed or the DB doesn't exist.

    Returns True if a row was updated, False otherwise.
    """
    db = db_path or get_db_path()
    if not db.exists():
        return False
    with _db_write_lock:
        conn = _get_connection(db)
        try:
            cursor = conn.execute(
                "UPDATE functions SET name = ? "
                "WHERE binary_id = (SELECT id FROM binaries WHERE sha256 = ?) "
                "AND address = ?",
                (new_name, sha256, address),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()


def sync_all_renames(
    sha256: str,
    renames: Dict[str, str],
    db_path: Optional[Path] = None,
) -> int:
    """Bulk-sync all function renames to the BSim DB.

    Parameters
    ----------
    sha256 : str
        SHA256 of the binary.
    renames : dict
        Mapping of hex address string → new name (from state.renames["functions"]).

    Returns the number of rows updated.
    """
    db = db_path or get_db_path()
    if not db.exists() or not renames:
        return 0
    updated = 0
    with _db_write_lock:
        conn = _get_connection(db)
        try:
            binary_row = conn.execute(
                "SELECT id FROM binaries WHERE sha256 = ?", (sha256,)
            ).fetchone()
            if not binary_row:
                return 0
            binary_id = binary_row[0]
            for addr_str, name in renames.items():
                try:
                    addr_int = int(addr_str, 16)
                    cursor = conn.execute(
                        "UPDATE functions SET name = ? "
                        "WHERE binary_id = ? AND address = ?",
                        (name, binary_id, addr_int),
                    )
                    updated += cursor.rowcount
                except (ValueError, TypeError):
                    continue
            conn.commit()
            return updated
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
            "SELECT sha256, filename, architecture, function_count, indexed_at, "
            "file_size, source, library_name "
            "FROM binaries ORDER BY indexed_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# Bounds on compare_indexed_binaries — defends against pathological inputs
# (e.g. 50K-function binaries) that would otherwise hold a dashboard worker
# thread for many minutes. Tunable via env vars for the rare cases that
# need them.
BSIM_COMPARE_MAX_CANDIDATES = 200          # cap candidate list size per fa
BSIM_COMPARE_BLOCK_TOLERANCE = 5           # absolute ±k blocks (was ±50%)
BSIM_COMPARE_MAX_FUNCS_PER_SIDE = 50000    # refuse comparison above this
BSIM_COMPARE_TIME_BUDGET_S = 30.0          # per-pair wallclock cap


def is_binary_indexed(sha256: str, db_path: Optional[Path] = None,
                      conn: Optional[sqlite3.Connection] = None) -> bool:
    """Quick check whether *sha256* has any rows in the BSim DB.

    Accepts an optional pre-opened connection for callers (e.g. project
    comparison) that need to check many binaries in a row without paying
    the connect/close cost per call. Falls back to opening its own
    connection when ``conn`` is None.
    """
    if conn is None:
        db = db_path or get_db_path()
        if not db.exists():
            return False
        c = _get_connection(db)
        owns = True
    else:
        c = conn
        owns = False
    try:
        row = c.execute(
            "SELECT 1 FROM binaries WHERE sha256 = ? LIMIT 1",
            (sha256.lower(),),
        ).fetchone()
        return row is not None
    finally:
        if owns:
            c.close()


def is_binaries_indexed_batch(sha256_list: List[str],
                              db_path: Optional[Path] = None,
                              conn: Optional[sqlite3.Connection] = None) -> Dict[str, bool]:
    """Batch ``is_binary_indexed`` for many sha256s in one query.

    Returns a ``{sha256: bool}`` map covering every input sha256 (False for
    those not in the DB). Replaces N round-trips with one ``IN (...)``
    query — meaningful when the project comparison view checks 100+ members
    at a time.
    """
    if not sha256_list:
        return {}
    wanted = {s.lower() for s in sha256_list if s}
    if not wanted:
        return {}
    out: Dict[str, bool] = {sha: False for sha in wanted}
    if conn is None:
        db = db_path or get_db_path()
        if not db.exists():
            return out
        c = _get_connection(db)
        owns = True
    else:
        c = conn
        owns = False
    try:
        # SQLite has no IN-list parameter binding, but `?, ?, ?` works
        # fine for any reasonable number of items. Bind the wanted set
        # in chunks to stay under SQLITE_MAX_VARIABLE_NUMBER (default 999).
        wanted_list = list(wanted)
        chunk = 500
        for i in range(0, len(wanted_list), chunk):
            sub = wanted_list[i:i + chunk]
            placeholders = ",".join("?" * len(sub))
            for row in c.execute(
                f"SELECT sha256 FROM binaries WHERE sha256 IN ({placeholders})",
                sub,
            ):
                out[row["sha256"]] = True
        return out
    finally:
        if owns:
            c.close()


def compare_indexed_binaries(
    sha_a: str,
    sha_b: str,
    threshold: float = BSIM_DEFAULT_THRESHOLD,
    metrics: str = "combined",
    top_match_limit: int = 50,
    db_path: Optional[Path] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Dict[str, Any]:
    """Compare two BSim-indexed binaries function-by-function from the DB.

    For each non-trivial function in *sha_a*, finds the best-scoring
    function from *sha_b* via ``compute_similarity`` (no angr project
    required — features are reconstructed from the DB rows). Aggregates
    the results into a per-pair similarity report suitable for the
    project comparison view.

    Bounded by:
      - ``BSIM_COMPARE_MAX_FUNCS_PER_SIDE`` — refuse before extraction
      - ``BSIM_COMPARE_BLOCK_TOLERANCE`` — strict ±k blocks (NOT ±50%) so
        small functions don't pull in the entire B function set
      - ``BSIM_COMPARE_MAX_CANDIDATES`` — cap candidate list per fa
      - ``BSIM_COMPARE_TIME_BUDGET_S`` — wallclock cap; remaining funcs
        skipped if exceeded

    The optional ``conn`` parameter lets project-level comparison reuse a
    single sqlite connection across many pair calls instead of opening a
    fresh one each time.

    Returns
    -------
    dict with keys:
      - ``available``: bool — both binaries are indexed
      - ``error``: str — present only when one or both binaries are missing
      - ``binary_a`` / ``binary_b``: ``{sha256, filename, function_count}``
      - ``shared_function_count``: int — min(matched_a, matched_b)
      - ``matched_a_count`` / ``matched_b_count``: int
      - ``jaccard``: float — shared / |union(A, B)|, always in [0, 1]
      - ``avg_similarity``: float — mean of best-match scores
      - ``top_matches``: list of ``{a_addr, a_name, b_addr, b_name, score}``
      - ``truncated``: bool — present when the time budget was hit
    """
    import time as _time

    sha_a = sha_a.lower()
    sha_b = sha_b.lower()
    if sha_a == sha_b:
        return {"available": False, "error": "Cannot compare a binary against itself"}

    if conn is None:
        db = db_path or get_db_path()
        if not db.exists():
            return {"available": False, "error": "BSim DB does not exist"}
        c = _get_connection(db)
        owns = True
    else:
        c = conn
        owns = False

    try:
        # Pull metadata for both binaries upfront so we can short-circuit
        # cleanly if either is unindexed.
        meta = {}
        for sha in (sha_a, sha_b):
            row = c.execute(
                "SELECT sha256, filename, function_count, architecture "
                "FROM binaries WHERE sha256 = ? LIMIT 1",
                (sha,),
            ).fetchone()
            if row is None:
                return {
                    "available": False,
                    "error": f"Binary {sha[:12]} is not indexed in BSim DB",
                    "missing_sha256": sha,
                }
            meta[sha] = dict(row)

        # Refuse comparison entirely if either side is too large — protects
        # the dashboard executor from runaway feature scoring on huge
        # binaries (e.g. stripped Go binaries with 50K+ functions).
        for sha, m in meta.items():
            fc = int(m.get("function_count") or 0)
            if fc > BSIM_COMPARE_MAX_FUNCS_PER_SIDE:
                return {
                    "available": False,
                    "error": (
                        f"Binary {sha[:12]} has {fc} indexed functions, "
                        f"exceeding the comparison cap "
                        f"({BSIM_COMPARE_MAX_FUNCS_PER_SIDE}). Comparing "
                        f"binaries this size would block the dashboard."
                    ),
                }

        # Pull all functions for each binary in one shot.
        def _load_funcs(sha: str) -> List[Dict[str, Any]]:
            cur = c.execute(
                "SELECT f.* FROM functions f "
                "JOIN binaries b ON f.binary_id = b.id "
                "WHERE b.sha256 = ?",
                (sha,),
            )
            out = []
            for row in cur:
                feats = _row_to_features(row)
                feats["_addr_int"] = int(row["address"])
                feats["_block_count"] = int(row["block_count"] or 0)
                feats["_instr_count"] = int(row["instruction_count"] or 0)
                out.append(feats)
            return out

        funcs_a = _load_funcs(sha_a)
        funcs_b = _load_funcs(sha_b)
    finally:
        if owns:
            c.close()

    if not funcs_a or not funcs_b:
        return {
            "available": True,
            "binary_a": meta[sha_a],
            "binary_b": meta[sha_b],
            "shared_function_count": 0,
            "matched_a_count": 0,
            "matched_b_count": 0,
            "jaccard": 0.0,
            "avg_similarity": 0.0,
            "total_functions_a": len(funcs_a),
            "total_functions_b": len(funcs_b),
            "top_matches": [],
            "note": "One or both binaries have no indexed functions",
        }

    # For each function in A, find the best-scoring counterpart in B.
    # Pre-bucket B by block count for cheap O(1) shortlist filtering. The
    # tolerance is a strict ±k absolute window (default 5), NOT a ±50%
    # relative window — the relative formula collapsed to ``[0, hi]`` for
    # any function with ≤4 blocks, which is most of any binary, defeating
    # the bucket entirely and producing O(|A|*|B|) scoring.
    b_by_blocks: Dict[int, List[Dict[str, Any]]] = {}
    for fb in funcs_b:
        b_by_blocks.setdefault(fb["_block_count"], []).append(fb)

    pair_scores: List[Dict[str, Any]] = []
    score_key = metrics if metrics else "combined"
    deadline = _time.monotonic() + BSIM_COMPARE_TIME_BUDGET_S
    truncated = False

    for fa in funcs_a:
        if _time.monotonic() > deadline:
            truncated = True
            break
        fa_blocks = fa["_block_count"]
        lo = max(0, fa_blocks - BSIM_COMPARE_BLOCK_TOLERANCE)
        hi = fa_blocks + BSIM_COMPARE_BLOCK_TOLERANCE
        candidates: List[Dict[str, Any]] = []
        for bk in range(lo, hi + 1):
            bucket = b_by_blocks.get(bk)
            if bucket:
                candidates.extend(bucket)
                if len(candidates) >= BSIM_COMPARE_MAX_CANDIDATES:
                    candidates = candidates[:BSIM_COMPARE_MAX_CANDIDATES]
                    break
        if not candidates:
            continue
        best = None
        best_score = 0.0
        for fb in candidates:
            scores = compute_similarity(fa, fb, metrics=score_key)
            score = scores.get(score_key, scores.get("combined", 0.0))
            if score > best_score:
                best_score = score
                best = (fb, scores)
        if best is None or best_score < threshold:
            continue
        fb, scores = best
        pair_scores.append({
            "a_address": hex(fa["_addr_int"]),
            "a_name": fa.get("name") or f"sub_{fa['_addr_int']:x}",
            "b_address": hex(fb["_addr_int"]),
            "b_name": fb.get("name") or f"sub_{fb['_addr_int']:x}",
            "score": round(best_score, 4),
            "scores": {k: round(v, 4) if isinstance(v, float) else v for k, v in scores.items()},
        })

    pair_scores.sort(key=lambda p: p["score"], reverse=True)

    total_a = len(funcs_a)
    total_b = len(funcs_b)
    # Each pair_scores entry corresponds to a unique A function (we picked
    # the single best B match per A above), so |matched_A| == len(pair_scores).
    # Multiple A functions may pick the SAME B function, so |matched_B| is a
    # set count, not a list count. The shared-function count is the smaller
    # of the two — that's the number of "actually shared" function pairs you
    # could form without re-using either side. Without this normalisation
    # the jaccard formula goes >1.0 when |A| >> |B| and many A funcs collide
    # onto the same B match.
    matched_a = len(pair_scores)
    matched_b = len({p["b_address"] for p in pair_scores})
    shared = min(matched_a, matched_b)
    union = max(total_a + total_b - shared, 1)
    jaccard = shared / union
    avg_sim = (sum(p["score"] for p in pair_scores) / matched_a) if matched_a else 0.0

    result = {
        "available": True,
        "binary_a": meta[sha_a],
        "binary_b": meta[sha_b],
        "threshold": threshold,
        "metrics": score_key,
        "shared_function_count": shared,
        "matched_a_count": matched_a,
        "matched_b_count": matched_b,
        "jaccard": round(jaccard, 4),
        "avg_similarity": round(avg_sim, 4),
        "total_functions_a": total_a,
        "total_functions_b": total_b,
        "top_matches": pair_scores[:top_match_limit],
    }
    if truncated:
        result["truncated"] = True
        result["note"] = (
            f"Hit {BSIM_COMPARE_TIME_BUDGET_S}s time budget; results are partial."
        )
    return result


def _safe_json_loads(raw, default):
    """Parse JSON with fallback to *default* on decode errors."""
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Corrupted JSON in BSim DB column, using default")
        return default


def _row_to_features(row: sqlite3.Row) -> Dict[str, Any]:
    """Reconstruct a feature dict from a database row for scoring."""
    cfg_structural = _safe_json_loads(row["cfg_structural_json"], {})
    size_metrics = _safe_json_loads(row["size_metrics_json"], {})
    api_calls = _safe_json_loads(row["api_calls_json"], {})
    string_hashes = _safe_json_loads(row["string_hashes_json"], [])
    constants = _safe_json_loads(row["constants_json"], [])
    vex_histogram = _safe_json_loads(row["vex_op_histogram_json"], {})

    # New feature groups — gracefully handle old DB rows that lack these columns
    try:
        block_hashes = _safe_json_loads(row["block_hashes_json"], [])
    except (IndexError, KeyError):
        block_hashes = []
    try:
        call_context = _safe_json_loads(row["call_context_json"], {})
    except (IndexError, KeyError):
        call_context = {}

    return {
        "address": row["address"],
        "name": row["name"],
        "cfg_structural": cfg_structural,
        "api_calls": api_calls if isinstance(api_calls, dict) else {"names": [], "categories": [], "count": 0},
        "string_refs": {"hashes": string_hashes, "count": len(string_hashes)},
        "constants": {"values": constants, "count": len(constants)},
        "_vex_histogram": vex_histogram,
        "size_metrics": size_metrics,
        "block_hashes": {"hashes": block_hashes, "count": len(block_hashes)} if isinstance(block_hashes, list) else block_hashes,
        "call_context": call_context if isinstance(call_context, dict) else {"import_callees": [], "import_callers": [], "callee_count": 0, "caller_count": 0},
    }
