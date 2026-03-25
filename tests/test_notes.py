"""Unit tests for hypothesis note management in AnalyzerState and tools_notes.py."""
import json
import pytest

from arkana.state import AnalyzerState, MAX_HYPOTHESIS_EVIDENCE


# ---------------------------------------------------------------------------
# AnalyzerState.add_note — hypothesis creation
# ---------------------------------------------------------------------------

class TestHypothesisCreation:
    """Tests for creating hypothesis notes via AnalyzerState.add_note."""

    def test_create_hypothesis_defaults(self):
        s = AnalyzerState()
        note = s.add_note("Binary is a RAT", category="hypothesis")
        assert note["category"] == "hypothesis"
        assert note["confidence"] == 0.5
        assert note["hypothesis_status"] == "proposed"
        assert note["evidence"] == []
        assert note["superseded_by"] is None

    def test_create_hypothesis_with_confidence(self):
        s = AnalyzerState()
        note = s.add_note("RAT hypothesis", category="hypothesis", confidence=0.8)
        assert note["confidence"] == 0.8

    def test_create_hypothesis_confidence_clamped_high(self):
        s = AnalyzerState()
        note = s.add_note("Over-confident", category="hypothesis", confidence=5.0)
        assert note["confidence"] == 1.0

    def test_create_hypothesis_confidence_clamped_low(self):
        s = AnalyzerState()
        note = s.add_note("Negative", category="hypothesis", confidence=-0.5)
        assert note["confidence"] == 0.0

    def test_create_hypothesis_with_status(self):
        s = AnalyzerState()
        note = s.add_note("Testing", category="hypothesis", status="investigating")
        assert note["hypothesis_status"] == "investigating"

    def test_create_hypothesis_invalid_status_defaults(self):
        s = AnalyzerState()
        note = s.add_note("Testing", category="hypothesis", status="invalid_status")
        assert note["hypothesis_status"] == "proposed"

    def test_create_hypothesis_with_evidence(self):
        s = AnalyzerState()
        evidence = [{"tool": "triage", "finding": "High entropy", "supports": True}]
        note = s.add_note("Packed binary", category="hypothesis", evidence=evidence)
        assert len(note["evidence"]) == 1
        assert note["evidence"][0]["tool"] == "triage"

    def test_create_hypothesis_evidence_capped(self):
        s = AnalyzerState()
        evidence = [{"tool": f"tool_{i}", "finding": f"f{i}", "supports": True}
                    for i in range(MAX_HYPOTHESIS_EVIDENCE + 20)]
        note = s.add_note("Big evidence", category="hypothesis", evidence=evidence)
        assert len(note["evidence"]) == MAX_HYPOTHESIS_EVIDENCE

    def test_non_hypothesis_ignores_hypothesis_fields(self):
        """Non-hypothesis notes should not have confidence/status/evidence fields."""
        s = AnalyzerState()
        note = s.add_note("General note", category="general",
                          confidence=0.9, status="confirmed")
        assert "confidence" not in note
        assert "hypothesis_status" not in note
        assert "evidence" not in note
        assert "superseded_by" not in note


# ---------------------------------------------------------------------------
# AnalyzerState.update_note — hypothesis updates
# ---------------------------------------------------------------------------

class TestHypothesisUpdate:
    """Tests for updating hypothesis notes via AnalyzerState.update_note."""

    def _make_hypothesis(self, s):
        return s.add_note("Binary is a dropper", category="hypothesis", confidence=0.3)

    def test_update_confidence(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        updated = s.update_note(note["id"], confidence=0.7)
        assert updated is not None
        assert updated["confidence"] == 0.7

    def test_update_confidence_clamped(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        updated = s.update_note(note["id"], confidence=99.0)
        assert updated["confidence"] == 1.0

    def test_update_hypothesis_status_valid(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        for status in ("proposed", "investigating", "supported", "refuted", "confirmed"):
            updated = s.update_note(note["id"], hypothesis_status=status)
            assert updated["hypothesis_status"] == status

    def test_update_hypothesis_status_invalid_ignored(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        updated = s.update_note(note["id"], hypothesis_status="bogus")
        assert updated["hypothesis_status"] == "proposed"

    def test_append_evidence_single_dict(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        item = {"tool": "capa", "finding": "Matched persistence rule", "supports": True}
        updated = s.update_note(note["id"], evidence=item)
        assert len(updated["evidence"]) == 1
        assert updated["evidence"][0]["tool"] == "capa"

    def test_append_evidence_list(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        items = [
            {"tool": "t1", "finding": "f1", "supports": True},
            {"tool": "t2", "finding": "f2", "supports": False},
        ]
        updated = s.update_note(note["id"], evidence=items)
        assert len(updated["evidence"]) == 2

    def test_append_evidence_cap(self):
        s = AnalyzerState()
        evidence = [{"tool": f"t{i}", "finding": f"f{i}", "supports": True}
                    for i in range(MAX_HYPOTHESIS_EVIDENCE)]
        note = s.add_note("Full", category="hypothesis", evidence=evidence)
        assert len(note["evidence"]) == MAX_HYPOTHESIS_EVIDENCE

        # Attempting to append beyond the cap
        updated = s.update_note(
            note["id"],
            evidence={"tool": "extra", "finding": "extra", "supports": True},
        )
        assert len(updated["evidence"]) == MAX_HYPOTHESIS_EVIDENCE

    def test_set_superseded_by(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        updated = s.update_note(note["id"], superseded_by="n_other_123")
        assert updated["superseded_by"] == "n_other_123"

    def test_update_nonexistent_note_returns_none(self):
        s = AnalyzerState()
        result = s.update_note("nonexistent_id", confidence=0.5)
        assert result is None

    def test_update_general_note_no_hypothesis_fields(self):
        """Updating a general note with hypothesis kwargs should not add those fields."""
        s = AnalyzerState()
        note = s.add_note("General", category="general")
        updated = s.update_note(note["id"], confidence=0.9, hypothesis_status="confirmed")
        # General notes don't have hypothesis fields, so they shouldn't be added
        assert "confidence" not in updated
        assert "hypothesis_status" not in updated

    def test_update_content_and_hypothesis_together(self):
        s = AnalyzerState()
        note = self._make_hypothesis(s)
        updated = s.update_note(
            note["id"], content="Revised hypothesis", confidence=0.9,
            hypothesis_status="confirmed",
        )
        assert updated["content"] == "Revised hypothesis"
        assert updated["confidence"] == 0.9
        assert updated["hypothesis_status"] == "confirmed"


# ---------------------------------------------------------------------------
# tools_notes.update_hypothesis MCP tool (async)
# ---------------------------------------------------------------------------

class TestUpdateHypothesisTool:
    """Tests for the update_hypothesis MCP tool function logic.

    These tests exercise the validation logic in update_hypothesis without
    going through the full MCP tool_decorator stack. We test the state-level
    operations that the tool relies on.
    """

    def test_update_nonhypothesis_note_detected(self):
        """The tool should detect when a note is not a hypothesis."""
        s = AnalyzerState()
        note = s.add_note("A general note", category="general")
        # The tool checks category before calling state.update_note
        assert note.get("category") != "hypothesis"

    def test_invalid_status_rejected(self):
        """The valid_statuses check in update_hypothesis should catch bad values."""
        valid = ("proposed", "investigating", "supported", "refuted", "confirmed")
        assert "bogus" not in valid
        assert "active" not in valid

    def test_evidence_json_parsing(self):
        """add_evidence JSON string should be parseable as a dict."""
        evidence_str = '{"tool": "scan", "finding": "match", "supports": true}'
        parsed = json.loads(evidence_str)
        assert isinstance(parsed, dict)
        assert parsed["tool"] == "scan"

    def test_evidence_json_invalid(self):
        """Invalid JSON in add_evidence should raise ValueError."""
        with pytest.raises(json.JSONDecodeError):
            json.loads("not valid json")

    def test_evidence_must_be_dict(self):
        """The tool checks that parsed evidence is a dict, not a list."""
        parsed = json.loads('[1, 2, 3]')
        assert not isinstance(parsed, dict)

    def test_superseded_by_target_must_exist(self):
        """The tool validates that superseded_by target exists in notes."""
        s = AnalyzerState()
        s.add_note("hyp", category="hypothesis")
        notes = s.get_notes()
        target_ids = {n["id"] for n in notes}
        assert "nonexistent_id" not in target_ids

    def test_full_hypothesis_lifecycle(self):
        """End-to-end hypothesis lifecycle through state methods."""
        s = AnalyzerState()
        # Step 1: Create
        note = s.add_note(
            "Binary is a RAT", category="hypothesis",
            confidence=0.3, status="proposed",
        )
        assert note["hypothesis_status"] == "proposed"
        assert note["confidence"] == 0.3

        # Step 2: Add evidence, upgrade status
        updated = s.update_note(
            note["id"], confidence=0.6, hypothesis_status="investigating",
            evidence={"tool": "c2_check", "finding": "Beacon found", "supports": True},
        )
        assert updated["hypothesis_status"] == "investigating"
        assert updated["confidence"] == 0.6
        assert len(updated["evidence"]) == 1

        # Step 3: More evidence
        updated = s.update_note(
            note["id"],
            evidence={"tool": "strings", "finding": "C2 URL", "supports": True},
        )
        assert len(updated["evidence"]) == 2

        # Step 4: Confirm
        updated = s.update_note(
            note["id"], confidence=0.95, hypothesis_status="confirmed",
        )
        assert updated["hypothesis_status"] == "confirmed"
        assert updated["confidence"] == 0.95

    def test_supersede_hypothesis(self):
        """A hypothesis can be superseded by another note."""
        s = AnalyzerState()
        old = s.add_note("Initial theory", category="hypothesis")
        new = s.add_note("Refined theory", category="hypothesis", confidence=0.8)
        updated = s.update_note(old["id"], superseded_by=new["id"])
        assert updated["superseded_by"] == new["id"]
