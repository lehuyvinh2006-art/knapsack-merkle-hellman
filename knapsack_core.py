"""Lõi thuật toán Merkle–Hellman knapsack (phiên bản đầy đủ).

Module này chỉ chứa thuật toán: không in, không đọc file, không giao diện.

Ký hiệu:
    W = (w1..wn)  dãy siêu tăng (khoá bí mật)
    q             modulus, q > sum(W)
    r             hệ số nhân, gcd(r, q) = 1
    B = (b1..bn)  khoá công khai, bi = r * wi mod q
"""
import secrets
from dataclasses import dataclass
from typing import List, Sequence

from number_theory import gcd, mod_inverse


@dataclass(frozen=True)
class PublicKey:
    B: List[int]

    @property
    def n(self) -> int:
        return len(self.B)


@dataclass(frozen=True)
class PrivateKey:
    W: List[int]
    q: int
    r: int
    r_inv: int

    @property
    def n(self) -> int:
        return len(self.W)


# --------------------------------------------------------------------------
# Sinh khoá
# --------------------------------------------------------------------------
def is_superincreasing(W: Sequence[int]) -> bool:
    """Kiểm tra wi > w1 + ... + w(i-1) với mọi i."""
    total = 0
    for w in W:
        if w <= total:
            return False
        total += w
    return True


def generate_superincreasing(n: int) -> List[int]:
    """Sinh dãy siêu tăng n phần tử: wi = (tổng các phần tử trước) + số ngẫu nhiên >= 1."""
    W: List[int] = []
    total = 0
    for _ in range(n):
        w = total + 1 + secrets.randbelow(2 ** n)
        W.append(w)
        total += w
    return W


def generate_keys(n: int = 64):
    """Sinh cặp khoá (PublicKey, PrivateKey) cho khối n bit (n chia hết cho 8)."""
    if n <= 0 or n % 8 != 0:
        raise ValueError("n phải dương và chia hết cho 8 (khối gồm nguyên số byte)")

    W = generate_superincreasing(n)               # 1. dãy siêu tăng
    q = sum(W) + 1 + secrets.randbelow(2 ** n)    # 2. q > tổng W
    while True:                                   # 3. r nguyên tố cùng nhau với q
        r = 2 + secrets.randbelow(q - 3)          #    1 < r < q
        if gcd(r, q) == 1:
            break
    B = [(r * w) % q for w in W]                  # 4. khoá công khai
    r_inv = mod_inverse(r, q)                     # 5. r^-1 mod q
    return PublicKey(B), PrivateKey(W, q, r, r_inv)


def make_public_key(W: Sequence[int], q: int, r: int):
    """Dựng khoá từ tham số cho trước (dùng để thử với số liệu cụ thể)."""
    if not is_superincreasing(W):
        raise ValueError("W không phải dãy siêu tăng")
    if q <= sum(W):
        raise ValueError("cần q > tổng W")
    if gcd(r, q) != 1:
        raise ValueError("cần gcd(r, q) = 1")
    B = [(r * w) % q for w in W]
    return PublicKey(B), PrivateKey(list(W), q, r, mod_inverse(r, q))


# --------------------------------------------------------------------------
# Mã hoá / giải mã một khối bit
# --------------------------------------------------------------------------
def encrypt_block(bits: Sequence[int], pub: PublicKey) -> int:
    """C = sum(xi * bi) cho khối bit x = (x1..xn)."""
    if len(bits) != pub.n:
        raise ValueError("độ dài khối bit phải bằng n")
    return sum(b for x, b in zip(bits, pub.B) if x)


def decrypt_block(C: int, priv: PrivateKey) -> List[int]:
    """Giải mã một block và từ chối bản mã không có biểu diễn chuẩn.

    Lưu ý: kiểm tra biểu diễn chuẩn không thay thế MAC/chữ ký số và không
    phát hiện được mọi kiểu sửa đổi bản mã.
    """
    if type(C) is not int or C < 0:
        raise ValueError("bản mã phải là số nguyên không âm")

    c = (C * priv.r_inv) % priv.q
    bits = [0] * priv.n
    for i in range(priv.n - 1, -1, -1):
        if c >= priv.W[i]:
            bits[i] = 1
            c -= priv.W[i]
    if c != 0:
        raise ValueError("bản mã không hợp lệ với khóa này (phần dư khác 0)")

    # Dựng lại bản mã từ các bit vừa giải mã. Ví dụ C + q cho cùng kết quả
    # modulo q, nhưng không phải biểu diễn chuẩn của block đã mã hóa.
    public_weights = [(priv.r * w) % priv.q for w in priv.W]
    canonical_C = sum(bit * b for bit, b in zip(bits, public_weights))
    if C != canonical_C:
        raise ValueError("bản mã không ở dạng chuẩn hoặc đã bị thay đổi")

    return bits
