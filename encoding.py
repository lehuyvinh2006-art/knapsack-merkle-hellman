"""Chuyển đổi bytes <-> khối bit, kèm đệm PKCS#7.

Mỗi khối gồm n bit = n/8 byte. Đệm luôn được thêm (kể cả khi độ dài đã vừa
khít), nên khi giải mã luôn gỡ được đệm một cách rõ ràng.
"""
from typing import List


def pad(data: bytes, block_bytes: int) -> bytes:
    if not 1 <= block_bytes <= 255:
        raise ValueError("block_bytes phải trong khoảng 1..255")
    k = block_bytes - (len(data) % block_bytes)
    return data + bytes([k]) * k


def unpad(data: bytes, block_bytes: int) -> bytes:
    if not data or len(data) % block_bytes:
        raise ValueError("dữ liệu giải mã có độ dài không hợp lệ")
    k = data[-1]
    if not 1 <= k <= block_bytes or data[-k:] != bytes([k]) * k:
        raise ValueError("đệm không hợp lệ (sai khoá hoặc bản mã bị sửa)")
    return data[:-k]


def bytes_to_bits(block: bytes) -> List[int]:
    """Mỗi byte thành 8 bit, bit cao (MSB) trước."""
    return [(byte >> s) & 1 for byte in block for s in range(7, -1, -1)]


def bits_to_bytes(bits: List[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("số bit phải chia hết cho 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def split_blocks(data: bytes, block_bytes: int) -> List[bytes]:
    return [data[i:i + block_bytes] for i in range(0, len(data), block_bytes)]
