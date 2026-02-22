"""SSDeep fuzzy hashing implementation."""
import io
import mmap


class SSDeep:
    BLOCKSIZE_MIN = 3
    SPAMSUM_LENGTH = 64
    STREAM_BUFF_SIZE = 8192
    HASH_PRIME = 0x01000193
    HASH_INIT = 0x28021967
    ROLL_WINDOW = 7
    B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    class _RollState(object):
        ROLL_WINDOW = 7

        def __init__(self):
            self.win = bytearray(self.ROLL_WINDOW)
            self.h1 = int()
            self.h2 = int()
            self.h3 = int()
            self.n = int()

        def roll_hash(self, b):
            self.h2 = (self.h2 - self.h1 + (self.ROLL_WINDOW * b)) & 0xFFFFFFFF
            self.h1 = (self.h1 + b - self.win[self.n % self.ROLL_WINDOW]) & 0xFFFFFFFF
            self.win[self.n % self.ROLL_WINDOW] = b
            self.n += 1
            self.h3 = (self.h3 << 5) & 0xFFFFFFFF
            self.h3 ^= b
            return self.h1 + self.h2 + self.h3

    def _spamsum(self, stream, slen):
        # Cache instance constants as locals for faster access in the tight loop.
        ROLL_WINDOW = self.ROLL_WINDOW
        HASH_PRIME = self.HASH_PRIME
        HASH_INIT = self.HASH_INIT
        SPAMSUM_LENGTH = self.SPAMSUM_LENGTH
        STREAM_BUFF_SIZE = self.STREAM_BUFF_SIZE
        BLOCKSIZE_MIN = self.BLOCKSIZE_MIN
        B64 = self.B64

        bs = BLOCKSIZE_MIN
        if slen > 0:
            while (bs * SPAMSUM_LENGTH) < slen:
                bs = bs * 2
        block_size = bs

        while True:
            stream.seek(0)
            roll_h1 = roll_h2 = roll_h3_val = 0
            roll_n = 0
            roll_win = bytearray(ROLL_WINDOW)
            block_hash1 = HASH_INIT
            block_hash2 = HASH_INIT
            # Use lists instead of string concatenation to avoid O(n^2)
            # cost from repeated immutable-string rebuilding.
            hash_chars1 = []
            hash_chars2 = []
            max_len1 = SPAMSUM_LENGTH - 1
            max_len2 = (SPAMSUM_LENGTH // 2) - 1

            buf = stream.read(STREAM_BUFF_SIZE)
            while buf:
                for b_val in buf:
                    block_hash1 = ((block_hash1 * HASH_PRIME) & 0xFFFFFFFF) ^ b_val
                    block_hash2 = ((block_hash2 * HASH_PRIME) & 0xFFFFFFFF) ^ b_val

                    roll_h2 = (roll_h2 - roll_h1 + (ROLL_WINDOW * b_val)) & 0xFFFFFFFF
                    roll_h1 = (roll_h1 + b_val - roll_win[roll_n % ROLL_WINDOW]) & 0xFFFFFFFF
                    roll_win[roll_n % ROLL_WINDOW] = b_val
                    roll_n += 1
                    roll_h3_val = (roll_h3_val << 5) & 0xFFFFFFFF
                    roll_h3_val ^= b_val

                    rh = roll_h1 + roll_h2 + roll_h3_val

                    if (rh % block_size) == (block_size - 1):
                        if len(hash_chars1) < max_len1:
                            hash_chars1.append(B64[block_hash1 % 64])
                            block_hash1 = HASH_INIT
                        if (rh % (block_size * 2)) == ((block_size * 2) - 1):
                            if len(hash_chars2) < max_len2:
                                hash_chars2.append(B64[block_hash2 % 64])
                                block_hash2 = HASH_INIT
                buf = stream.read(STREAM_BUFF_SIZE)

            if block_size > BLOCKSIZE_MIN and len(hash_chars1) < (SPAMSUM_LENGTH // 2):
                block_size = (block_size // 2)
            else:
                if roll_n > 0:
                    if len(hash_chars1) < SPAMSUM_LENGTH:
                        hash_chars1.append(B64[block_hash1 % 64])
                    if len(hash_chars2) < max_len2 + 1:
                        hash_chars2.append(B64[block_hash2 % 64])
                break
        return f'{block_size}:{"".join(hash_chars1)}:{"".join(hash_chars2)}'

    def hash(self, buf_data_input):
        buf_data_bytes = None
        if isinstance(buf_data_input, bytes):
            buf_data_bytes = buf_data_input
        elif isinstance(buf_data_input, str):
            buf_data_bytes = buf_data_input.encode('utf-8', 'ignore')
        elif isinstance(buf_data_input, mmap.mmap):
            buf_data_bytes = buf_data_input[:]
        else:
            raise TypeError(f"Argument must be of bytes, string, or mmap.mmap type, not {type(buf_data_input)}")

        if not buf_data_bytes:
            bs = self.BLOCKSIZE_MIN
            return f"{bs}::"

        return self._spamsum(io.BytesIO(buf_data_bytes), len(buf_data_bytes))

    def _levenshtein(self, s, t):
        if s == t: return 0
        len_s = len(s)
        len_t = len(t)
        if len_s == 0: return len_t
        if len_t == 0: return len_s
        v0 = list(range(len_t + 1))
        v1 = [0] * (len_t + 1)
        for i in range(len_s):
            v1[0] = i + 1
            s_i = s[i]
            for j in range(len_t):
                cost = 0 if s_i == t[j] else 1
                v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
            # Swap references instead of copying element by element.
            v0, v1 = v1, v0
        return v0[len_t]

    def _common_substring(self, s1, s2):
        ROLL_WINDOW = self.ROLL_WINDOW
        hashes = []
        roll = self._RollState()
        for ch in s1:
            hashes.append(roll.roll_hash(ord(ch)))

        # Build a dict mapping hash -> list of indices for O(1) lookups
        # instead of scanning the full hashes list for every s2 position.
        hash_index = {}
        for j, h in enumerate(hashes):
            if j >= ROLL_WINDOW - 1 and h != 0:
                hash_index.setdefault(h, []).append(j)

        roll = self._RollState()
        for i, ch in enumerate(s2):
            rh = roll.roll_hash(ord(ch))
            if i < ROLL_WINDOW - 1:
                continue
            candidates = hash_index.get(rh)
            if candidates:
                ir = i - (ROLL_WINDOW - 1)
                s2_window = s2[ir:ir + ROLL_WINDOW]
                if len(s2_window) < ROLL_WINDOW:
                    continue
                for j in candidates:
                    jr = j - (ROLL_WINDOW - 1)
                    if s2_window == s1[jr:jr + ROLL_WINDOW]:
                        return True
        return False

    def _score_strings(self, s1, s2, block_size):
        if not self._common_substring(s1, s2):
            return 0
        if not s1 or not s2:
            return 0

        lev_score = self._levenshtein(s1, s2)
        sum_len = len(s1) + len(s2)
        if sum_len == 0:
            return 100

        score = (lev_score * self.SPAMSUM_LENGTH) // sum_len
        score = (100 * score) // self.SPAMSUM_LENGTH
        score = 100 - score

        min_len_s1_s2 = min(len(s1), len(s2)) if len(s1) > 0 and len(s2) > 0 else 0
        if min_len_s1_s2 > 0:
            cap_val = (block_size // self.BLOCKSIZE_MIN) * min_len_s1_s2
            if score > cap_val:
                score = cap_val
        elif not s1 and not s2:
            score = 100
        else:
            score = 0
        return score

    def _strip_sequences(self, s):
        if len(s) <= 3:
            return s
        # Use list accumulation instead of repeated string concatenation.
        parts = [s[0], s[1], s[2]]
        for i in range(3, len(s)):
            if s[i] != s[i-1] or s[i] != s[i-2] or s[i] != s[i-3]:
                parts.append(s[i])
        return ''.join(parts)

    def compare(self, hash1_str, hash2_str):
        if not (isinstance(hash1_str, str) and isinstance(hash2_str, str)):
            raise TypeError('Arguments must be of string type')
        try:
            hash1_parts = hash1_str.split(':', 2)
            hash2_parts = hash2_str.split(':', 2)
            if len(hash1_parts) != 3 or len(hash2_parts) != 3:
                    raise ValueError('Invalid hash format (must have 3 parts)')

            hash1_bs_str, hash1_s1, hash1_s2 = hash1_parts
            hash2_bs_str, hash2_s1, hash2_s2 = hash2_parts

            hash1_bs = int(hash1_bs_str)
            hash2_bs = int(hash2_bs_str)
        except ValueError as e:
            raise ValueError(f'Invalid hash format: {e}') from None

        if hash1_bs != hash2_bs and hash1_bs != (hash2_bs * 2) and hash2_bs != (hash1_bs * 2):
            return 0

        hash1_s1 = self._strip_sequences(hash1_s1)
        hash1_s2 = self._strip_sequences(hash1_s2)
        hash2_s1 = self._strip_sequences(hash2_s1)
        hash2_s2 = self._strip_sequences(hash2_s2)

        if hash1_bs == hash2_bs and hash1_s1 == hash2_s1:
            return 100

        score = 0
        if hash1_bs == hash2_bs:
            score1 = self._score_strings(hash1_s1, hash2_s1, hash1_bs)
            score2 = self._score_strings(hash1_s2, hash2_s2, hash2_bs)
            score = int(max([score1, score2]))
        elif hash1_bs == (hash2_bs * 2):
            score = int(self._score_strings(hash1_s1, hash2_s2, hash1_bs))
        else:  # hash2_bs == (hash1_bs * 2)
            score = int(self._score_strings(hash1_s2, hash2_s1, hash2_bs))
        return score


ssdeep_hasher = SSDeep()
