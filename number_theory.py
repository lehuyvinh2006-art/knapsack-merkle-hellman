"""Số học cơ bản tự cài đặt: gcd, Euclid mở rộng, nghịch đảo modulo.

Không dùng math.gcd / pow(x, -1, m) ở đây; các hàm thư viện chuẩn chỉ
được dùng trong bộ kiểm thử để đối chiếu.
"""


def gcd(a: int, b: int) -> int:
    """Ước chung lớn nhất (Euclid)."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    """Euclid mở rộng: trả về (g, x, y) thoả a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return old_r, old_x, old_y


def mod_inverse(a: int, m: int) -> int:
    """Nghịch đảo của a modulo m, tức a^-1 sao cho a * a^-1 ≡ 1 (mod m).

    Ném ValueError nếu gcd(a, m) != 1.
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("a và m không nguyên tố cùng nhau, không có nghịch đảo")
    return x % m
