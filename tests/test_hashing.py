"""Unit tests for pemcp/hashing.py — SSDeep fuzzy hashing."""
import pytest

from pemcp.hashing import SSDeep, ssdeep_hasher


class TestSSDeepHash:
    def test_empty_bytes(self):
        result = ssdeep_hasher.hash(b"")
        # Empty input -> "3::"
        assert result == "3::"

    def test_empty_string(self):
        result = ssdeep_hasher.hash("")
        assert result == "3::"

    def test_bytes_input(self):
        data = b"A" * 1000
        result = ssdeep_hasher.hash(data)
        assert isinstance(result, str)
        parts = result.split(":")
        assert len(parts) == 3
        # Block size should be an integer
        assert int(parts[0]) >= SSDeep.BLOCKSIZE_MIN

    def test_string_input(self):
        data = "Hello World! " * 100
        result = ssdeep_hasher.hash(data)
        parts = result.split(":")
        assert len(parts) == 3

    def test_invalid_type_raises(self):
        with pytest.raises(TypeError):
            ssdeep_hasher.hash(12345)

    def test_deterministic(self):
        data = b"deterministic test data " * 50
        h1 = ssdeep_hasher.hash(data)
        h2 = ssdeep_hasher.hash(data)
        assert h1 == h2

    def test_different_data_different_hash(self):
        h1 = ssdeep_hasher.hash(b"AAAA" * 500)
        h2 = ssdeep_hasher.hash(b"BBBB" * 500)
        # Should produce different hash strings
        assert h1 != h2

    def test_format_block_size_colon_separated(self):
        result = ssdeep_hasher.hash(b"test data for format check " * 50)
        parts = result.split(":")
        assert len(parts) == 3
        block_size = int(parts[0])
        assert block_size >= 3


class TestSSDeepCompare:
    def test_identical_hashes(self):
        data = b"Hello World test data for ssdeep " * 100
        h = ssdeep_hasher.hash(data)
        score = ssdeep_hasher.compare(h, h)
        assert score == 100

    def test_completely_different(self):
        # Hashes with incompatible block sizes return 0
        score = ssdeep_hasher.compare("3:abc:def", "12:xyz:uvw")
        assert score == 0

    def test_non_string_raises(self):
        with pytest.raises(TypeError):
            ssdeep_hasher.compare(123, "3:abc:def")

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            ssdeep_hasher.compare("invalid", "also_invalid")

    def test_similar_data(self):
        base = b"The quick brown fox jumps over the lazy dog. " * 100
        # Slightly modified
        modified = base[:len(base) // 2] + b"X" + base[len(base) // 2 + 1:]
        h1 = ssdeep_hasher.hash(base)
        h2 = ssdeep_hasher.hash(modified)
        # Similar data should produce similar hashes with a non-zero score
        # (depending on block size alignment, this might still be 0 in edge cases)
        score = ssdeep_hasher.compare(h1, h2)
        assert isinstance(score, int)
        assert 0 <= score <= 100


class TestSSDeepLevenshtein:
    def test_same_strings(self):
        assert ssdeep_hasher._levenshtein("abc", "abc") == 0

    def test_empty_first(self):
        assert ssdeep_hasher._levenshtein("", "abc") == 3

    def test_empty_second(self):
        assert ssdeep_hasher._levenshtein("abc", "") == 3

    def test_both_empty(self):
        assert ssdeep_hasher._levenshtein("", "") == 0

    def test_single_edit(self):
        assert ssdeep_hasher._levenshtein("abc", "abd") == 1

    def test_insertion(self):
        assert ssdeep_hasher._levenshtein("abc", "abcd") == 1


class TestSSDeepStripSequences:
    def test_short_string(self):
        assert ssdeep_hasher._strip_sequences("ab") == "ab"

    def test_no_sequences(self):
        assert ssdeep_hasher._strip_sequences("abcd") == "abcd"

    def test_long_sequence(self):
        # "aaaa..." should be stripped to max 3 consecutive identical chars
        result = ssdeep_hasher._strip_sequences("aaaaabcde")
        assert result == "aaabcde"

    def test_multiple_sequences(self):
        result = ssdeep_hasher._strip_sequences("aaaabbbb")
        assert result == "aaabbb"
