"""
Simplified Advanced Cryptanalysis Utilities
Supports 7 classical attack methods on VigHill cipher.
"""

import numpy as np
import string
from collections import Counter
from math import gcd
from functools import reduce

class AdvancedCryptanalysis:
    
    ENGLISH_IC = 0.0667
    
    ENGLISH_FREQ = {
        'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
        'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
        'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
        'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
        'U': 0.028, 'V': 0.010, 'W': 0.024, 'X': 0.002, 'Y': 0.020, 'Z': 0.001
    }

    def index_of_coincidence(self, text):
        text = ''.join(filter(str.isalpha, text)).upper()
        N = len(text)
        if N <= 1:
            return 0.0
        counter = Counter(text)
        sum_freq = sum(count * (count - 1) for count in counter.values())
        return sum_freq / (N * (N - 1))

    def chi_squared_test(self, text):
        text = ''.join(filter(str.isalpha, text)).upper()
        N = len(text)
        if N == 0:
            return float('inf')
        counter = Counter(text)
        chi_sq = 0.0
        for letter in string.ascii_uppercase:
            observed = counter.get(letter, 0)
            expected = N * self.ENGLISH_FREQ[letter]
            if expected > 0:
                chi_sq += ((observed - expected) ** 2) / expected
        return chi_sq

    def frequency_analysis(self, ciphertext):
        text = ''.join(filter(str.isalpha, ciphertext)).upper()
        total = len(text)
        if total == 0:
            return {'frequencies': {}, 'chi_squared': float('inf'), 'total_chars': 0}
        counter = Counter(text)
        frequencies = {letter: (count / total) * 100 for letter, count in counter.items()}
        return {
            'frequencies': frequencies,
            'chi_squared': self.chi_squared_test(text),
            'total_chars': total
        }

    def find_key_length_ic(self, ciphertext, max_key_length=20):
        text = ''.join(filter(str.isalpha, ciphertext)).upper()
        best_len, best_diff = 1, float('inf')
        for L in range(1, max_key_length + 1):
            cols = ['' for _ in range(L)]
            for i, c in enumerate(text):
                cols[i % L] += c
            ics = [self.index_of_coincidence(col) for col in cols if col]
            avg_ic = sum(ics) / len(ics) if ics else 0
            diff = abs(avg_ic - self.ENGLISH_IC)
            if diff < best_diff:
                best_diff, best_len = diff, L
        return best_len

    def kasiski_examination(self, ciphertext, min_seq_len=3):
        text = ''.join(filter(str.isalpha, ciphertext)).upper()
        distances = []
        max_check = min(len(text) // 2, 10)
        for seq_len in range(min_seq_len, max_check + 1):
            seen = {}
            for i in range(len(text) - seq_len + 1):
                seq = text[i:i+seq_len]
                if seq in seen:
                    seen[seq].append(i)
                else:
                    seen[seq] = [i]
            for positions in seen.values():
                if len(positions) >= 2:
                    for i in range(len(positions)):
                        for j in range(i + 1, len(positions)):
                            distances.append(positions[j] - positions[i])
        if distances:
            return reduce(gcd, distances)
        return None

    def break_vigenere_with_known_length(self, ciphertext, key_length):
        text = ''.join(filter(str.isalpha, ciphertext)).upper()
        key = []
        for pos in range(key_length):
            col = [text[i] for i in range(pos, len(text), key_length)]
            best_shift, best_score = 0, float('inf')
            for shift in range(26):
                decrypted = ''.join(chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in col)
                score = self.chi_squared_test(decrypted)
                if score < best_score:
                    best_score, best_shift = score, shift
            key.append(chr(best_shift + ord('A')))
        return ''.join(key)

    def ciphertext_only_attack(self, ciphertext):
        key_len_ic = self.find_key_length_ic(ciphertext, max_key_length=15)
        key_len_kasiski = self.kasiski_examination(ciphertext)
        if key_len_kasiski and abs(key_len_kasiski - key_len_ic) <= 2:
            key_len = key_len_kasiski
        else:
            key_len = key_len_ic
        return self.break_vigenere_with_known_length(ciphertext, key_len)

    def known_plaintext_attack_hill(self, plain_blocks, cipher_blocks):
        if len(plain_blocks) < 3 or len(cipher_blocks) < 3:
            return None
        try:
            P = np.array([[ord(c) - ord('A') for c in block] for block in plain_blocks[:3]]).T
            C = np.array([[ord(c) - ord('A') for c in block] for block in cipher_blocks[:3]]).T
            det = int(round(np.linalg.det(P))) % 26
            det_inv = self._mod_inverse(det, 26)
            if det_inv is None:
                return None
            P_inv_float = np.linalg.inv(P)
            P_adj = np.round(det * P_inv_float).astype(int)
            P_inv = (det_inv * P_adj) % 26
            K = np.dot(C, P_inv) % 26
            return K.astype(int)
        except Exception:
            return None

    def _mod_inverse(self, a, m):
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None