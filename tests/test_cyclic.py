"""Unit tests for De Bruijn cyclic pattern generation and lookup."""

import pytest
from pwnwindbg.commands.cyclic_cmds import cyclic, cyclic_find, _de_bruijn


class TestDeBruijn:
    """Tests for the core De Bruijn sequence generator."""

    def test_de_bruijn_length(self):
        """The sequence length should be k**n."""
        seq = _de_bruijn(2, 3)
        assert len(seq) == 2 ** 3
        # Every 3-mer should appear exactly once
        triples = {seq[i:i + 3] for i in range(len(seq) - 2)}
        assert len(triples) == 8

    def test_de_bruijn_alphabet(self):
        """The alphabet should be the first k lowercase letters."""
        seq = _de_bruijn(3, 2)
        assert set(seq) <= {"a", "b", "c"}


class TestCyclic:
    """Tests for the user-facing cyclic() helper."""

    def test_cyclic_exact_length(self):
        """cyclic(length) should return exactly ``length`` characters."""
        for length in (4, 8, 100, 256, 1000):
            pat = cyclic(length)
            assert len(pat) == length

    def test_cyclic_content(self):
        """The pattern should only contain a-z."""
        pat = cyclic(500)
        assert pat.isalpha()
        assert pat.islower()

    def test_cyclic_subsequence_uniqueness(self):
        """In a long enough pattern, every 4-byte subsequence should be unique."""
        pat = cyclic(1000, n=4)
        subs = [pat[i:i + 4] for i in range(len(pat) - 3)]
        assert len(subs) == len(set(subs))

    def test_cyclic_64bit_subsequence_uniqueness(self):
        """Every 8-byte subsequence should be unique in the 64-bit pattern."""
        pat = cyclic(2000, n=8)
        subs = [pat[i:i + 8] for i in range(len(pat) - 7)]
        assert len(subs) == len(set(subs))


class TestCyclicFind:
    """Tests for cyclic_find() offset lookup."""

    def test_find_ascii_subsequence(self):
        """Look up a raw ASCII subsequence."""
        pat = cyclic(200)
        offset = cyclic_find("aaab")
        assert offset == 3
        assert pat[offset:offset + 4] == "aaab"

    def test_find_int_little_endian(self):
        """Look up an int interpreted as little-endian bytes."""
        # "aaab" as little-endian dword
        val = int.from_bytes(b"aaab", "little")
        offset = cyclic_find(val, n=4)
        assert offset == 3

    def test_find_int_64bit(self):
        """Look up an int interpreted as little-endian qword."""
        val = int.from_bytes(b"aaaaaaab", "little")
        offset = cyclic_find(val, n=8)
        assert offset == 7

    def test_find_not_found(self):
        """Non-existent subsequence should return -1."""
        assert cyclic_find("!!!!") == -1
        assert cyclic_find(0xFFFFFFFF) == -1

    def test_find_zero_offset(self):
        """The very first subsequence should be at offset 0."""
        assert cyclic_find("aaaa", n=4) == 0
        assert cyclic_find("aaaaaaaa", n=8) == 0

    def test_find_repeated_pattern(self):
        """cyclic_find should work against the large internal pattern."""
        pat = cyclic(0x10000)
        for expected_off in (0, 50, 100, 1000, 5000):
            sub = pat[expected_off:expected_off + 4]
            assert cyclic_find(sub, n=4) == expected_off
