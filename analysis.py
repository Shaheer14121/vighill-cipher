import numpy as np
import time
import sys

# ----------------------------
# VigHillCipher (Minimal Core)
# ----------------------------

class VigHillCipher:
    def __init__(self, vigenere_key, hill_key_matrix):
        if len(vigenere_key) < 10:
            raise ValueError("Vigenère key must be at least 10 characters")
        self.vigenere_key = vigenere_key.upper()
        self.hill_key = np.array(hill_key_matrix)
        self.hill_key_inv = self._matrix_mod_inv(self.hill_key, 26)
        if self.hill_key_inv is None:
            raise ValueError("Hill matrix not invertible mod 26")

    def _matrix_mod_inv(self, matrix, modulus):
        det = int(round(np.linalg.det(matrix)))
        det_inv = self._mod_inverse(det % modulus, modulus)
        if det_inv is None:
            return None
        matrix_adj = np.round(det * np.linalg.inv(matrix)).astype(int)
        return (det_inv * matrix_adj) % modulus

    def _mod_inverse(self, a, m):
        a %= m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    def _vigenere_encrypt(self, pt):
        res = []
        L = len(self.vigenere_key)
        for i, c in enumerate(pt):
            if c.isalpha():
                shift = ord(self.vigenere_key[i % L]) - ord('A')
                res.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                res.append(c)
        return ''.join(res)

    def _vigenere_decrypt(self, ct):
        res = []
        L = len(self.vigenere_key)
        for i, c in enumerate(ct):
            if c.isalpha():
                shift = ord(self.vigenere_key[i % L]) - ord('A')
                res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
            else:
                res.append(c)
        return ''.join(res)

    def _hill_encrypt(self, text):
        clean = ''.join(filter(str.isalpha, text)).upper()
        while len(clean) % 3: clean += 'X'
        out = []
        for i in range(0, len(clean), 3):
            vec = np.array([ord(c) - ord('A') for c in clean[i:i+3]])
            enc = np.dot(self.hill_key, vec) % 26
            out.append(''.join(chr(int(x) + ord('A')) for x in enc))
        return ''.join(out)

    def _hill_decrypt(self, text):
        clean = ''.join(filter(str.isalpha, text)).upper()
        out = []
        for i in range(0, len(clean), 3):
            vec = np.array([ord(c) - ord('A') for c in clean[i:i+3]])
            dec = np.dot(self.hill_key_inv, vec) % 26
            out.append(''.join(chr(int(x) + ord('A')) for x in dec))
        return ''.join(out)

    def encrypt(self, plaintext):
        pt = ''.join(filter(str.isalpha, plaintext)).upper()
        return self._hill_encrypt(self._vigenere_encrypt(pt))

    def decrypt(self, ciphertext):
        return self._vigenere_decrypt(self._hill_decrypt(ciphertext))


# ----------------------------
# Performance Benchmark
# ----------------------------

def benchmark():
    # Fixed keys for reproducibility
    vigenere_key = "PERFORMANCEKEY"  # 15 chars
    hill_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # invertible

    try:
        cipher = VigHillCipher(vigenere_key, hill_matrix)
    except Exception as e:
        print(f"❌ Cipher setup failed: {e}")
        return

    text_lengths = [100, 500, 1000, 5000, 10000]
    results = []

    print("=" * 60)
    print("VIGHILL CIPHER — PERFORMANCE ANALYSIS")
    print("=" * 60)

    # Warm-up run
    warmup = 'A' * 1000
    cipher.encrypt(warmup)
    cipher.decrypt(cipher.encrypt(warmup))

    for n in text_lengths:
        plaintext = 'A' * n

        # Encryption time
        start = time.perf_counter()
        ciphertext = cipher.encrypt(plaintext)
        end = time.perf_counter()
        enc_time_ms = (end - start) * 1000

        # Decryption time
        start = time.perf_counter()
        decrypted = cipher.decrypt(ciphertext)
        end = time.perf_counter()
        dec_time_ms = (end - start) * 1000

        results.append((n, enc_time_ms, dec_time_ms))

    # ----------------------------
    # Output: Theoretical Complexity
    # ----------------------------

    print("\n📊 TIME COMPLEXITY")
    print("-" * 40)
    print(f"{'Operation':<20} {'Complexity':<12} {'Explanation'}")
    print("-" * 40)
    print(f"{'Vigenère Encryption':<20} {'O(n)':<12} Single pass through text")
    print(f"{'Vigenère Decryption':<20} {'O(n)':<12} Single pass through text")
    print(f"{'Hill Encryption':<20} {'O(n)':<12} Processes n/3 blocks, constant-time matrix ops")
    print(f"{'Hill Decryption':<20} {'O(n)':<12} Same as encryption")
    print(f"{'Total Encryption':<20} {'O(n)':<12} Sequential application")
    print(f"{'Total Decryption':<20} {'O(n)':<12} Sequential application")

    print("\n💾 SPACE COMPLEXITY")
    print("-" * 40)
    print("• O(1) - Constant space for keys and matrices")
    print("  Keys stored once, reused for all operations")

    # ----------------------------
    # Output: Empirical Performance
    # ----------------------------

    print("\n⏱️  EMPIRICAL PERFORMANCE")
    print("Measured on standard hardware:")
    print("-" * 50)
    print(f"{'Text Length':<15} {'Encryption Time':<20} {'Decryption Time'}")
    print("-" * 50)
    for n, enc_ms, dec_ms in results:
        print(f"{n:<15} ~{enc_ms:.1f} ms{'':<12} ~{dec_ms:.1f} ms")

    # ----------------------------
    # Output: Comparison with Simple Ciphers
    # ----------------------------

    print("\n⚖️  COMPARISON WITH SIMPLE CIPHERS")
    print("-" * 50)
    print("Shift Cipher (Caesar):")
    print("• Time Complexity: O(n)")
    print("• Very fast constant factor")
    print("• Minimal overhead")
    print("\nVigHill Cipher:")
    print("• Time Complexity: O(n)")
    print("• Higher constant factor (2× operations)")
    print("• Matrix operations add overhead")
    print("• Trade-off: ~2× slower, but significantly more secure")

    print("\n" + "=" * 60)
    print("✅ BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    benchmark()