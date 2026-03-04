"""Unit tests for custom type (struct/enum) state accessors."""
import pytest
from arkana.state import AnalyzerState


@pytest.fixture
def state():
    return AnalyzerState()


class TestCreateStruct:
    def test_basic_struct(self, state):
        fields = [{"name": "magic", "type": "uint32_le"}, {"name": "size", "type": "uint16_le"}]
        result = state.create_struct("TestStruct", fields, 6)
        assert result["name"] == "TestStruct"
        assert result["type"] == "struct"
        assert result["size"] == 6
        assert len(result["fields"]) == 2
        assert "created_at" in result

    def test_struct_stored(self, state):
        fields = [{"name": "x", "type": "uint8"}]
        state.create_struct("S1", fields, 1)
        assert "S1" in state.custom_types["structs"]

    def test_overwrite_struct(self, state):
        state.create_struct("S1", [{"name": "x", "type": "uint8"}], 1)
        state.create_struct("S1", [{"name": "y", "type": "uint16_le"}], 2)
        assert state.custom_types["structs"]["S1"]["size"] == 2


class TestCreateEnum:
    def test_basic_enum(self, state):
        values = {"CMD_PING": 1, "CMD_EXEC": 2}
        result = state.create_enum("CommandID", values, 4)
        assert result["name"] == "CommandID"
        assert result["type"] == "enum"
        assert result["size"] == 4
        assert result["values"]["CMD_PING"] == 1

    def test_enum_stored(self, state):
        state.create_enum("E1", {"A": 0}, 1)
        assert "E1" in state.custom_types["enums"]


class TestGetCustomType:
    def test_get_struct(self, state):
        state.create_struct("S1", [{"name": "x", "type": "uint8"}], 1)
        result = state.get_custom_type("S1")
        assert result is not None
        assert result["type"] == "struct"
        assert result["name"] == "S1"

    def test_get_enum(self, state):
        state.create_enum("E1", {"A": 0}, 1)
        result = state.get_custom_type("E1")
        assert result is not None
        assert result["type"] == "enum"

    def test_get_nonexistent(self, state):
        assert state.get_custom_type("nope") is None


class TestGetAll:
    def test_get_all_types(self, state):
        state.create_struct("S1", [{"name": "x", "type": "uint8"}], 1)
        state.create_enum("E1", {"A": 0}, 1)
        result = state.get_all_custom_types()
        assert "S1" in result["structs"]
        assert "E1" in result["enums"]


class TestDelete:
    def test_delete_struct(self, state):
        state.create_struct("S1", [{"name": "x", "type": "uint8"}], 1)
        assert state.delete_custom_type("S1") is True
        assert state.get_custom_type("S1") is None

    def test_delete_enum(self, state):
        state.create_enum("E1", {"A": 0}, 1)
        assert state.delete_custom_type("E1") is True

    def test_delete_nonexistent(self, state):
        assert state.delete_custom_type("nope") is False


class TestSnapshot:
    def test_snapshot_returns_copy(self, state):
        state.create_struct("S1", [{"name": "x", "type": "uint8"}], 1)
        snap = state.get_all_types_snapshot()
        snap["structs"]["S1"]["size"] = 999
        assert state.custom_types["structs"]["S1"]["size"] == 1


class TestClear:
    def test_clear(self, state):
        state.create_struct("S1", [{"name": "x", "type": "uint8"}], 1)
        state.create_enum("E1", {"A": 0}, 1)
        count = state.clear_custom_types()
        assert count == 2
        assert state.custom_types == {"structs": {}, "enums": {}}
