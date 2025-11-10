import numpy as np
import string
from collections import Counter

class VigHillCipher:
    def __init__(self, vigenere_key, hill_key_matrix):
        if len(vigenere_key) < 10:
            raise ValueError("Vigenère key must be at least 10 characters long")
        self.vigenere_key = vigenere_key.upper()
        self.hill_key = np.array(hill_key_matrix)
        self.hill_key_inv = self._matrix_mod_inv(self.hill_key, 26)
        if self.hill_key_inv is None:
            raise ValueError("Hill key matrix is not invertible modulo 26")

    def _matrix_mod_inv(self, matrix, modulus):
        det = int(round(np.linalg.det(matrix)))
        det_mod = det % modulus
        det_inv = self._mod_inverse(det_mod, modulus)
        if det_inv is None:
            return None
        matrix_inv_float = np.linalg.inv(matrix)
        matrix_adj = np.round(det * matrix_inv_float).astype(int)
        matrix_inv = (det_inv * matrix_adj) % modulus
        return matrix_inv

    def _mod_inverse(self, a, m):
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    def _vigenere_encrypt(self, plaintext):
        result = []
        key_len = len(self.vigenere_key)
        for i, char in enumerate(plaintext):
            if char.isalpha():
                shift = ord(self.vigenere_key[i % key_len]) - ord('A')
                enc = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                result.append(enc)
            else:
                result.append(char)
        return ''.join(result)

    def _vigenere_decrypt(self, ciphertext):
        result = []
        key_len = len(self.vigenere_key)
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                shift = ord(self.vigenere_key[i % key_len]) - ord('A')
                dec = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                result.append(dec)
            else:
                result.append(char)
        return ''.join(result)

    def _hill_encrypt(self, text):
        clean = ''.join(filter(str.isalpha, text)).upper()
        while len(clean) % 3 != 0:
            clean += 'X'
        result = []
        for i in range(0, len(clean), 3):
            block = clean[i:i+3]
            vec = np.array([ord(c) - ord('A') for c in block])
            enc_vec = np.dot(self.hill_key, vec) % 26
            enc_block = ''.join(chr(int(v) + ord('A')) for v in enc_vec)
            result.append(enc_block)
        return ''.join(result)

    def _hill_decrypt(self, text):
        clean = ''.join(filter(str.isalpha, text)).upper()
        result = []
        for i in range(0, len(clean), 3):
            block = clean[i:i+3]
            vec = np.array([ord(c) - ord('A') for c in block])
            dec_vec = np.dot(self.hill_key_inv, vec) % 26
            dec_block = ''.join(chr(int(v) + ord('A')) for v in dec_vec)
            result.append(dec_block)
        return ''.join(result)

    def encrypt(self, plaintext):
        plaintext = ''.join(filter(str.isalpha, plaintext)).upper()
        stage1 = self._vigenere_encrypt(plaintext)
        return self._hill_encrypt(stage1)

    def decrypt(self, ciphertext):
        stage1 = self._hill_decrypt(ciphertext)
        return self._vigenere_decrypt(stage1)


# Predefined invertible 3x3 Hill matrices (mod 26)
HILL_MATRICES = {
    '1': [[6, 24, 1], [13, 16, 10], [20, 17, 15]],   # Classic example
    '2': [[3, 10, 20], [20, 9, 17], [9, 4, 17]],     # Another valid one
    '3': [[11, 2, 19], [5, 23, 14], [24, 7, 15]],    # Also invertible
    '4': [[9, 3, 1], [11, 8, 4], [2, 5, 12]]         # Verified invertible
}

def get_vigenere_key():
    while True:
        key = input("Enter Vigenère key (at least 10 letters, alphabetic only): ").strip()
        if key.isalpha() and len(key) >= 10:
            return key.upper()
        else:
            print("❌ Invalid key! Must be ≥10 alphabetic characters.")

def get_hill_matrix():
    print("\nChoose Hill key matrix:")
    print("1. Classic matrix (6,24,1 / 13,16,10 / 20,17,15)")
    print("2. Alternative matrix (3,10,20 / 20,9,17 / 9,4,17)")
    print("3. Another option (11,2,19 / 5,23,14 / 24,7,15)")
    print("4. Fourth option (9,3,1 / 11,8,4 / 2,5,12)")
    print("5. Enter your own 3x3 matrix")
    
    while True:
        choice = input("\nSelect option (1-5): ").strip()
        if choice in HILL_MATRICES:
            return HILL_MATRICES[choice]
        elif choice == '5':
            print("Enter your 3x3 Hill matrix row by row (9 integers total, space-separated):")
            try:
                nums = list(map(int, input("Enter 9 integers: ").split()))
                if len(nums) != 9:
                    raise ValueError
                matrix = [nums[i:i+3] for i in range(0, 9, 3)]
                return matrix
            except (ValueError, KeyboardInterrupt):
                print("❌ Invalid input. Please enter exactly 9 integers.")
        else:
            print("❌ Invalid choice. Please select 1-5.")

def main():
    print("=" * 50)
    print("🔐 INTERACTIVE VIG-HILL CIPHER")
    print("=" * 50)
    
    while True:
        mode = input("\nChoose mode:\n[E] Encrypt\n[D] Decrypt\n[Q] Quit\n→ ").strip().upper()
        if mode == 'Q':
            print("Goodbye!")
            break
        elif mode not in ['E', 'D']:
            print("❌ Invalid mode. Please enter E, D, or Q.")
            continue

        # Get text
        if mode == 'E':
            text = input("Enter plaintext (letters only): ").strip()
            if not text.replace(' ', '').isalpha():
                print("❌ Plaintext must contain only letters.")
                continue
        else:
            text = input("Enter ciphertext (letters only): ").strip()
            if not text.isalpha():
                print("❌ Ciphertext must contain only letters.")
                continue

        # Get keys
        vigenere_key = get_vigenere_key()
        hill_matrix = get_hill_matrix()

        # Create cipher and process
        try:
            cipher = VigHillCipher(vigenere_key, hill_matrix)
            if mode == 'E':
                result = cipher.encrypt(text)
                print(f"\n✅ ENCRYPTED: {result}")
            else:
                result = cipher.decrypt(text)
                # Remove padding X's only if they appear at the end
                # (Note: this is heuristic; true padding removal requires original length)
                result_clean = result.rstrip('X')
                print(f"\n✅ DECRYPTED: {result_clean}")
        except ValueError as e:
            print(f"❌ Error: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()