"""Bộ kiểm thử: ca tự viết + đối chiếu với thư viện chuẩn (math, itertools).

Chạy:  python test_knapsack.py           (in bảng PASS/FAIL)
   hoặc: python -m unittest test_knapsack -v
Knapsack không có test vector NIST/RFC (hệ mã đã bị phá, không được chuẩn
hoá), nên đối chiếu dùng các hàm thư viện chuẩn và vét cạn độc lập.
"""
import itertools
import math
import os
import secrets
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cipher import decrypt, decrypt_text, encrypt, encrypt_text
from encoding import bytes_to_bits
from knapsack_core import (decrypt_block, encrypt_block, generate_keys,
                           is_superincreasing, make_public_key)
from number_theory import extended_gcd, gcd, mod_inverse


# ---- mỗi ca trả về (kỳ vọng, thực tế) --------------------------------------
def case_roundtrip_exact_block():
    pub, priv = generate_keys(64)
    m = b"12345678"                      # đúng 1 khối 8 byte
    return m, decrypt(encrypt(m, pub), priv)


def case_roundtrip_needs_padding():
    pub, priv = generate_keys(64)
    m = b"khong chia het cho 8 byte!"    # 26 byte
    return m, decrypt(encrypt(m, pub), priv)


def case_roundtrip_vietnamese_utf8():
    pub, priv = generate_keys(128)
    m = "Mật mã học: hệ mã xếp ba lô Merkle–Hellman 🔐"
    return m, decrypt_text(encrypt_text(m, pub), priv)


def case_empty_and_extreme_bytes():
    pub, priv = generate_keys(64)
    msgs = [b"", b"\x00" * 20, b"\xff" * 20]
    return msgs, [decrypt(encrypt(m, pub), priv) for m in msgs]


def case_random_roundtrips():
    ok = 0
    for _ in range(200):
        pub, priv = generate_keys(secrets.choice([8, 16, 64, 128]))
        m = secrets.token_bytes(secrets.randbelow(60))
        ok += decrypt(encrypt(m, pub), priv) == m
    return 200, ok


def case_keys_valid():
    pub, priv = generate_keys(64)
    good = (is_superincreasing(priv.W) and priv.q > sum(priv.W)
            and math.gcd(priv.r, priv.q) == 1
            and pub.B == [(priv.r * w) % priv.q for w in priv.W])
    return True, good


def case_ref_number_theory():
    """So hàm tự cài với math.gcd và pow(x, -1, m)."""
    ok = True
    for _ in range(500):
        a, m = secrets.randbelow(10**12) + 1, secrets.randbelow(10**12) + 2
        ok &= gcd(a, m) == math.gcd(a, m)
        g, x, y = extended_gcd(a, m)
        ok &= a * x + m * y == g
        if math.gcd(a, m) == 1:
            ok &= mod_inverse(a, m) == pow(a, -1, m)
    return True, ok


def case_ref_bruteforce_small_n():
    """n=8: vét cạn 256 tổ hợp trên khoá công khai phải ra đúng bản rõ."""
    pub, priv = generate_keys(8)
    ok = True
    for byte in range(256):
        bits = bytes_to_bits(bytes([byte]))
        C = encrypt_block(bits, pub)
        found = [c for c in itertools.product((0, 1), repeat=8)
                 if sum(b for x, b in zip(c, pub.B) if x) == C]
        ok &= found == [tuple(bits)] and decrypt_block(C, priv) == bits
    return True, ok


def case_fixed_parameters():
    """Tham số cố định, đáp án tính tay: W=(2,7,11,21,42), q=105, r=31."""
    pub, priv = make_public_key([2, 7, 11, 21, 42], 105, 31)
    C = encrypt_block([1, 0, 1, 1, 0], pub)
    return ([62, 7, 26, 336 % 105, 42 * 31 % 105], 62 + 26 + 336 % 105,
            [1, 0, 1, 1, 0]), (pub.B, C, decrypt_block(C, priv))


def case_wrong_key_rejected():
    pub, _ = generate_keys(64)
    _, other = generate_keys(64)
    try:
        out = decrypt(encrypt(b"bi mat", pub), other)
        return "không giải ra bản rõ", "giải ra " + repr(out) if out == b"bi mat" else "không giải ra bản rõ"
    except ValueError:
        return "không giải ra bản rõ", "không giải ra bản rõ"


CASES = [
    ("Khứ hồi: đúng 1 khối", case_roundtrip_exact_block),
    ("Khứ hồi: cần đệm", case_roundtrip_needs_padding),
    ("Khứ hồi: tiếng Việt UTF-8 (n=128)", case_roundtrip_vietnamese_utf8),
    ("Biên: rỗng / toàn 0 / toàn 1", case_empty_and_extreme_bytes),
    ("Ngẫu nhiên 200 khoá & bản rõ", case_random_roundtrips),
    ("Khoá hợp lệ (siêu tăng, q, gcd)", case_keys_valid),
    ("Đối chiếu math.gcd / pow(-1)", case_ref_number_theory),
    ("Đối chiếu vét cạn n=8", case_ref_bruteforce_small_n),
    ("Tham số cố định tính tay", case_fixed_parameters),
    ("Sai khoá không giải ra bản rõ", case_wrong_key_rejected),
]


class KnapsackTests(unittest.TestCase):
    def test_all(self):
        for name, fn in CASES:
            with self.subTest(name):
                expected, actual = fn()
                self.assertEqual(expected, actual)


    def test_issue4_ciphertext_plus_modulus_is_rejected(self):
        pub, priv = generate_keys(8)
        bits = bytes_to_bits(b"A")
        original = encrypt_block(bits, pub)
        self.assertEqual(decrypt_block(original, priv), bits)
        with self.assertRaises(ValueError):
            decrypt_block(original + priv.q, priv)

    def test_issue4_invalid_ciphertext_types_are_rejected(self):
        _, priv = generate_keys(8)
        for value in (-1, "123", 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decrypt_block(value, priv)

    def test_issue5_missing_file_has_friendly_error(self):
        import subprocess
        import tempfile
        cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = os.path.join(temp_dir, "missing_private_key.json")
            result = subprocess.run(
                [sys.executable, cli_path, "decrypt", "--priv", missing],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Lỗi:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_issue5_malformed_json_has_friendly_error(self):
        import subprocess
        import tempfile
        cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_cipher = os.path.join(temp_dir, "bad_cipher.json")
            with open(bad_cipher, "w", encoding="utf-8") as file:
                file.write('[1, nope]')
            # The CLI parses the input JSON before loading/decrypting the key.
            result = subprocess.run(
                [sys.executable, cli_path, "decrypt", "--priv", "unused.json", "--in", bad_cipher],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("JSON không hợp lệ", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_issue5_non_list_ciphertext_has_friendly_error(self):
        import subprocess
        import tempfile
        cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            cipher_path = os.path.join(temp_dir, "not_list.json")
            with open(cipher_path, "w", encoding="utf-8") as file:
                file.write('{"cipher": 123}')
            result = subprocess.run(
                [sys.executable, cli_path, "decrypt", "--priv", "unused.json", "--in", cipher_path],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("danh sách JSON", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


def main() -> int:
    print(f"{'Ca kiểm thử':<40}{'Kết quả'}")
    print("-" * 52)
    failed = 0
    for name, fn in CASES:
        try:
            expected, actual = fn()
            status = "PASS" if expected == actual else "FAIL"
        except Exception as exc:  # noqa: BLE001
            status, expected, actual = "FAIL", "(không lỗi)", repr(exc)
        if status == "FAIL":
            failed += 1
            print(f"{name:<40}FAIL\n    kỳ vọng: {expected}\n    thực tế: {actual}")
        else:
            print(f"{name:<40}PASS")
    print("-" * 52)
    print(f"Tổng: {len(CASES) - failed}/{len(CASES)} ca đạt")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
