"""Unit tests for pemcp/mcp/tools_learning.py — learner progress tracking."""
import asyncio
import json
import pytest

from pathlib import Path

import pemcp.mcp.tools_learning as tl


def _run(coro):
    """Helper to run async functions in tests."""
    return asyncio.run(coro)


class MockContext:
    """Minimal mock for MCP Context used by tool tests."""
    def __init__(self):
        self.infos = []
        self.warnings = []

    async def info(self, msg):
        self.infos.append(msg)

    async def warning(self, msg):
        self.warnings.append(msg)


@pytest.fixture
def mock_ctx():
    return MockContext()


@pytest.fixture(autouse=True)
def _isolate_profile(tmp_path, monkeypatch):
    """Redirect profile storage to a temp directory for every test."""
    profile_dir = tmp_path / ".pemcp"
    profile_path = profile_dir / "learner_profile.json"
    monkeypatch.setattr(tl, "_PROFILE_DIR", profile_dir)
    monkeypatch.setattr(tl, "_PROFILE_PATH", profile_path)


# ---------------------------------------------------------------------------
#  _empty_profile
# ---------------------------------------------------------------------------

class TestEmptyProfile:
    def test_returns_valid_structure(self):
        p = tl._empty_profile()
        assert p["version"] == 1
        assert p["session_count"] == 0
        assert p["total_concepts_introduced"] == 0
        assert p["total_concepts_mastered"] == 0
        assert p["current_tier"] == "foundation"
        assert p["concepts"] == {}
        assert p["session_log"] == []
        assert "created_at" in p
        assert "updated_at" in p


# ---------------------------------------------------------------------------
#  _load_profile / _save_profile
# ---------------------------------------------------------------------------

class TestLoadProfile:
    def test_creates_fresh_when_file_missing(self):
        """When no profile file exists, _load_profile returns a fresh profile."""
        profile = tl._load_profile()
        assert profile["version"] == 1
        assert profile["session_count"] == 0

    def test_handles_corrupt_json(self, tmp_path):
        """Corrupt JSON on disk should be silently replaced with a fresh profile."""
        profile_path = tmp_path / ".pemcp" / "learner_profile.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text("NOT VALID JSON {{{", encoding="utf-8")
        profile = tl._load_profile()
        assert profile["version"] == 1
        assert profile["session_count"] == 0

    def test_handles_wrong_version(self, tmp_path):
        """A profile with unexpected version should be treated as corrupt."""
        profile_path = tmp_path / ".pemcp" / "learner_profile.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps({"version": 99}), encoding="utf-8")
        profile = tl._load_profile()
        assert profile["version"] == 1

    def test_handles_non_dict_json(self, tmp_path):
        """A profile that is valid JSON but not a dict should be treated as corrupt."""
        profile_path = tmp_path / ".pemcp" / "learner_profile.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        profile = tl._load_profile()
        assert profile["version"] == 1


class TestSaveProfile:
    def test_persists_and_reloads(self):
        """Saved profile should be loadable and contain the same data."""
        profile = tl._empty_profile()
        profile["session_count"] = 7
        profile["concepts"]["pe_headers"] = {
            "level": "practiced",
            "first_seen": "2025-01-01T00:00:00",
            "last_updated": "2025-01-02T00:00:00",
            "update_count": 2,
        }
        tl._save_profile(profile)

        loaded = tl._load_profile()
        assert loaded["session_count"] == 7
        assert loaded["concepts"]["pe_headers"]["level"] == "practiced"
        # updated_at should be refreshed by _save_profile
        assert loaded["updated_at"] is not None


# ---------------------------------------------------------------------------
#  _compute_tier
# ---------------------------------------------------------------------------

class TestComputeTier:
    def test_returns_foundation_for_empty_profile(self):
        profile = tl._empty_profile()
        assert tl._compute_tier(profile) == "foundation"

    def test_stays_foundation_below_70_percent(self):
        """If fewer than 70% of foundation concepts are mastered, tier stays foundation."""
        profile = tl._empty_profile()
        foundation_concepts = [
            cid for cid, info in tl._CONCEPT_CATALOG.items()
            if info["tier"] == "foundation"
        ]
        # Master only a small fraction
        count_needed = int(len(foundation_concepts) * 0.3)
        for cid in foundation_concepts[:count_needed]:
            profile["concepts"][cid] = {"level": "mastered"}
        assert tl._compute_tier(profile) == "foundation"

    def test_advances_at_70_percent_mastery(self):
        """With >= 70% foundation concepts mastered, should advance to intermediate."""
        profile = tl._empty_profile()
        foundation_concepts = [
            cid for cid, info in tl._CONCEPT_CATALOG.items()
            if info["tier"] == "foundation"
        ]
        # Master exactly 70% (rounded up to be safe)
        count_needed = int(len(foundation_concepts) * 0.7) + 1
        for cid in foundation_concepts[:count_needed]:
            profile["concepts"][cid] = {"level": "mastered"}
        tier = tl._compute_tier(profile)
        assert tier == "intermediate"

    def test_practiced_not_counted_as_mastered(self):
        """Only 'mastered' level counts toward tier advancement."""
        profile = tl._empty_profile()
        foundation_concepts = [
            cid for cid, info in tl._CONCEPT_CATALOG.items()
            if info["tier"] == "foundation"
        ]
        # Set all foundation concepts to 'practiced' (not mastered)
        for cid in foundation_concepts:
            profile["concepts"][cid] = {"level": "practiced"}
        assert tl._compute_tier(profile) == "foundation"

    def test_all_mastered_returns_expert(self):
        """If every concept in the catalog is mastered, tier is expert."""
        profile = tl._empty_profile()
        for cid in tl._CONCEPT_CATALOG:
            profile["concepts"][cid] = {"level": "mastered"}
        assert tl._compute_tier(profile) == "expert"

    def test_advances_through_multiple_tiers(self):
        """Master foundation and intermediate to reach advanced."""
        profile = tl._empty_profile()
        for cid, info in tl._CONCEPT_CATALOG.items():
            if info["tier"] in ("foundation", "intermediate"):
                profile["concepts"][cid] = {"level": "mastered"}
        tier = tl._compute_tier(profile)
        assert tier == "advanced"


# ---------------------------------------------------------------------------
#  _module_completion
# ---------------------------------------------------------------------------

class TestModuleCompletion:
    def test_calculates_correct_stats(self):
        profile = tl._empty_profile()
        # Module 1.2 has: pe_headers, pe_sections, entry_point, pe_resources
        profile["concepts"]["pe_headers"] = {"level": "mastered"}
        profile["concepts"]["pe_sections"] = {"level": "practiced"}
        profile["concepts"]["entry_point"] = {"level": "introduced"}
        # pe_resources is not started

        stats = tl._module_completion(profile, "1.2")
        assert stats["module"] == "1.2"
        assert stats["total"] == 4
        assert stats["mastered"] == 1
        assert stats["practiced"] == 1
        assert stats["introduced"] == 1
        assert stats["not_started"] == 1
        assert stats["completion_pct"] == 25  # 1 mastered / 4 total = 25%

    def test_empty_module_returns_zeros(self):
        """A module ID that has no concepts returns all zeros."""
        profile = tl._empty_profile()
        stats = tl._module_completion(profile, "99.99")
        assert stats["total"] == 0
        assert stats["mastered"] == 0
        assert stats["completion_pct"] == 0

    def test_fully_mastered_module(self):
        profile = tl._empty_profile()
        module_concepts = [
            cid for cid, info in tl._CONCEPT_CATALOG.items()
            if info["module"] == "1.3"
        ]
        for cid in module_concepts:
            profile["concepts"][cid] = {"level": "mastered"}
        stats = tl._module_completion(profile, "1.3")
        assert stats["completion_pct"] == 100
        assert stats["not_started"] == 0


# ---------------------------------------------------------------------------
#  update_concept_mastery (async MCP tool)
# ---------------------------------------------------------------------------

class TestUpdateConceptMastery:
    def test_invalid_concept_returns_error(self, mock_ctx):
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="totally_fake_concept", level="introduced"
        ))
        assert result["status"] == "error"
        assert "Unknown concept" in result["message"]
        assert "hint" in result

    def test_invalid_concept_suggests_close_matches(self, mock_ctx):
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_head", level="introduced"
        ))
        assert result["status"] == "error"
        assert "pe_headers" in result["did_you_mean"]

    def test_invalid_level_returns_error(self, mock_ctx):
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="expert_level"
        ))
        assert result["status"] == "error"
        assert "Invalid mastery level" in result["message"]

    def test_prevents_regression(self, mock_ctx):
        """A concept at 'mastered' cannot be downgraded to 'introduced'."""
        # First set it to mastered
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="mastered"
        ))
        # Attempt regression
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced"
        ))
        assert result["status"] == "warning"
        assert "cannot regress" in result["message"]
        assert result["current_level"] == "mastered"

    def test_prevents_regression_practiced_to_introduced(self, mock_ctx):
        """A concept at 'practiced' cannot be downgraded to 'introduced'."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_sections", level="practiced"
        ))
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_sections", level="introduced"
        ))
        assert result["status"] == "warning"
        assert result["current_level"] == "practiced"

    def test_allows_progression(self, mock_ctx):
        """introduced -> practiced -> mastered is allowed."""
        r1 = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced"
        ))
        assert r1["status"] == "success"
        assert r1["new_level"] == "introduced"
        assert r1["previous_level"] is None

        r2 = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="practiced"
        ))
        assert r2["status"] == "success"
        assert r2["new_level"] == "practiced"
        assert r2["previous_level"] == "introduced"

        r3 = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="mastered"
        ))
        assert r3["status"] == "success"
        assert r3["new_level"] == "mastered"
        assert r3["previous_level"] == "practiced"

    def test_same_level_update_allowed(self, mock_ctx):
        """Re-setting the same level should succeed (not count as regression)."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="practiced"
        ))
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="practiced"
        ))
        assert result["status"] == "success"

    def test_returns_module_completion(self, mock_ctx):
        """Result should include module completion stats."""
        result = _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced"
        ))
        assert "module_completion" in result
        assert result["module"] == "1.2"
        assert result["module_title"] == "PE Structure Deep Dive"
        assert result["tier"] == "foundation"

    def test_notes_stored_when_provided(self, mock_ctx):
        """Optional notes should be stored in the concept entry."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced",
            notes="Learned during PE walkthrough session"
        ))
        profile = tl._load_profile()
        assert profile["concepts"]["pe_headers"]["last_note"] == "Learned during PE walkthrough session"

    def test_notes_absent_when_not_provided(self, mock_ctx):
        """When notes is None, no last_note key should be set."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced"
        ))
        profile = tl._load_profile()
        assert "last_note" not in profile["concepts"]["pe_headers"]

    def test_update_count_increments(self, mock_ctx):
        """Each update should increment the update_count."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced"
        ))
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="practiced"
        ))
        profile = tl._load_profile()
        assert profile["concepts"]["pe_headers"]["update_count"] == 2


# ---------------------------------------------------------------------------
#  reset_learner_profile (async MCP tool)
# ---------------------------------------------------------------------------

class TestResetLearnerProfile:
    def test_without_confirm_returns_confirmation_required(self, mock_ctx):
        result = _run(tl.reset_learner_profile.__wrapped__(mock_ctx, confirm=False))
        assert result["status"] == "confirmation_required"
        assert "confirm=True" in result["message"]

    def test_default_confirm_returns_confirmation_required(self, mock_ctx):
        """The default (no confirm argument) should also require confirmation."""
        result = _run(tl.reset_learner_profile.__wrapped__(mock_ctx))
        assert result["status"] == "confirmation_required"

    def test_with_confirm_resets_profile(self, mock_ctx):
        """confirm=True should reset the profile and return previous stats."""
        # Set up some progress first
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="mastered"
        ))
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_sections", level="practiced"
        ))

        result = _run(tl.reset_learner_profile.__wrapped__(mock_ctx, confirm=True))
        assert result["status"] == "success"
        assert "previous_stats" in result
        assert result["previous_stats"]["concepts_tracked"] == 2
        assert result["previous_stats"]["mastered"] == 1

        # Verify the profile is actually fresh
        profile = tl._load_profile()
        assert profile["concepts"] == {}
        assert profile["session_count"] == 0

    def test_reset_sends_info_message(self, mock_ctx):
        """Reset should send a ctx.info notification."""
        _run(tl.reset_learner_profile.__wrapped__(mock_ctx, confirm=True))
        assert any("reset" in msg.lower() for msg in mock_ctx.infos)


# ---------------------------------------------------------------------------
#  get_learner_profile (async MCP tool)
# ---------------------------------------------------------------------------

class TestGetLearnerProfile:
    def test_increments_session_count(self, mock_ctx):
        """Each call should increment session_count."""
        r1 = _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        assert r1["session_count"] == 1
        r2 = _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        assert r2["session_count"] == 2

    def test_returns_expected_keys(self, mock_ctx):
        result = _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        expected_keys = {
            "status", "current_tier", "session_count", "total_concepts",
            "concepts_mastered", "concepts_practiced", "concepts_introduced",
            "concepts_not_started", "module_completion", "recent_sessions",
            "created_at", "updated_at",
        }
        assert expected_keys.issubset(result.keys())

    def test_fresh_profile_all_not_started(self, mock_ctx):
        result = _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        assert result["concepts_mastered"] == 0
        assert result["concepts_practiced"] == 0
        assert result["concepts_introduced"] == 0
        assert result["concepts_not_started"] == len(tl._CONCEPT_CATALOG)

    def test_reflects_mastery_updates(self, mock_ctx):
        """Profile should reflect concepts updated in previous calls."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="mastered"
        ))
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_sections", level="introduced"
        ))
        result = _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        assert result["concepts_mastered"] == 1
        assert result["concepts_introduced"] == 1

    def test_module_completion_included(self, mock_ctx):
        result = _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        assert isinstance(result["module_completion"], list)
        assert len(result["module_completion"]) > 0
        # Each entry should have expected keys
        for entry in result["module_completion"]:
            assert "module" in entry
            assert "total" in entry
            assert "completion_pct" in entry

    def test_session_log_capped_at_50(self, mock_ctx):
        """Session log should never exceed 50 entries."""
        # Create a profile with 50 session log entries already
        profile = tl._empty_profile()
        for i in range(55):
            profile["session_log"].append({
                "timestamp": f"2025-01-01T00:00:{i:02d}",
                "type": "session_start",
            })
        tl._save_profile(profile)

        # Call get_learner_profile which adds one more and trims
        _run(tl.get_learner_profile.__wrapped__(mock_ctx))
        reloaded = tl._load_profile()
        assert len(reloaded["session_log"]) <= 50


# ---------------------------------------------------------------------------
#  get_learning_suggestions (async MCP tool)
# ---------------------------------------------------------------------------

class TestGetLearningSuggestions:
    def test_fresh_profile_welcome_advice(self, mock_ctx):
        """A brand-new learner should get the welcome message."""
        result = _run(tl.get_learning_suggestions.__wrapped__(mock_ctx))
        assert result["status"] == "success"
        assert "Welcome" in result["advice"]
        assert result["current_tier"] == "foundation"

    def test_foundation_tier_advice(self, mock_ctx):
        """Learner with some progress at foundation tier gets appropriate advice."""
        # Master a few concepts so total_mastered > 0 but stay in foundation
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="mastered"
        ))
        result = _run(tl.get_learning_suggestions.__wrapped__(mock_ctx))
        assert "foundation" in result["advice"].lower() or "fundamentals" in result["advice"].lower()

    def test_tier_focus_filters_suggestions(self, mock_ctx):
        """Passing focus='intermediate' should target intermediate tier."""
        result = _run(tl.get_learning_suggestions.__wrapped__(
            mock_ctx, focus="intermediate"
        ))
        assert result["status"] == "success"
        assert result["target_tiers"] == ["intermediate"]

    def test_module_focus_returns_module_specific(self, mock_ctx):
        """Passing a module ID as focus should return module-specific suggestions."""
        result = _run(tl.get_learning_suggestions.__wrapped__(
            mock_ctx, focus="1.2"
        ))
        assert result["status"] == "success"
        assert result["module_focus"] == "1.2"
        assert result["module_title"] == "PE Structure Deep Dive"
        assert "concepts_to_start" in result
        assert "module_completion" in result

    def test_unknown_module_focus_returns_error(self, mock_ctx):
        """An invalid module ID should return an error."""
        result = _run(tl.get_learning_suggestions.__wrapped__(
            mock_ctx, focus="99.99"
        ))
        assert result["status"] == "error"
        assert "Unknown module" in result["message"]

    def test_module_focus_shows_in_progress(self, mock_ctx):
        """Module focus should list concepts that are in progress."""
        _run(tl.update_concept_mastery.__wrapped__(
            mock_ctx, concept="pe_headers", level="introduced"
        ))
        result = _run(tl.get_learning_suggestions.__wrapped__(
            mock_ctx, focus="1.2"
        ))
        assert "pe_headers" in result["concepts_to_practice"]

    def test_no_focus_returns_target_tiers(self, mock_ctx):
        """Without focus, result should include target_tiers for natural progression."""
        result = _run(tl.get_learning_suggestions.__wrapped__(mock_ctx))
        assert "target_tiers" in result
        assert "foundation" in result["target_tiers"]

    def test_includes_incomplete_modules(self, mock_ctx):
        result = _run(tl.get_learning_suggestions.__wrapped__(mock_ctx))
        assert "incomplete_modules" in result
        assert len(result["incomplete_modules"]) > 0

    def test_includes_concepts_to_start(self, mock_ctx):
        result = _run(tl.get_learning_suggestions.__wrapped__(mock_ctx))
        assert "concepts_to_start" in result
        assert len(result["concepts_to_start"]) > 0
        # Each suggestion should have expected keys
        for suggestion in result["concepts_to_start"]:
            assert "concept" in suggestion
            assert "module" in suggestion

    def test_intermediate_tier_advice(self, mock_ctx):
        """Learner at intermediate tier gets intermediate-level advice."""
        profile = tl._empty_profile()
        # Master all foundation concepts
        for cid, info in tl._CONCEPT_CATALOG.items():
            if info["tier"] == "foundation":
                profile["concepts"][cid] = {"level": "mastered"}
        # Master a few intermediate to push total_mastered > 0
        _run_count = 0
        for cid, info in tl._CONCEPT_CATALOG.items():
            if info["tier"] == "intermediate" and _run_count < 2:
                profile["concepts"][cid] = {"level": "mastered"}
                _run_count += 1
        tl._save_profile(profile)

        result = _run(tl.get_learning_suggestions.__wrapped__(mock_ctx))
        assert result["current_tier"] == "intermediate"
        assert "intermediate" in result["advice"].lower() or "decompilation" in result["advice"].lower()


# ---------------------------------------------------------------------------
#  Constants sanity checks
# ---------------------------------------------------------------------------

class TestConstants:
    def test_mastery_levels_ordering(self):
        assert tl.MASTERY_LEVELS == ("introduced", "practiced", "mastered")

    def test_tier_order(self):
        assert tl.TIER_ORDER == ("foundation", "intermediate", "advanced", "expert")

    def test_concept_catalog_not_empty(self):
        assert len(tl._CONCEPT_CATALOG) > 0

    def test_all_concepts_have_required_keys(self):
        for cid, info in tl._CONCEPT_CATALOG.items():
            assert "module" in info, f"Concept {cid} missing 'module'"
            assert "tier" in info, f"Concept {cid} missing 'tier'"
            assert "title" in info, f"Concept {cid} missing 'title'"
            assert info["tier"] in tl.TIER_ORDER, f"Concept {cid} has invalid tier '{info['tier']}'"
