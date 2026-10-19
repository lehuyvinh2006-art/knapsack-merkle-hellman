"""Ghép lõi knapsack với mã hoá/giải mã thông điệp (bytes hoặc chuỗi)."""
from typing import List

from encoding import (bits_to_bytes, bytes_to_bits, pad, split_blocks, unpad)
from knapsack_core import PrivateKey, PublicKey, decrypt_block, encrypt_block


def encrypt(message: bytes, pub: PublicKey) -> List[int]:
    """Bản rõ (bytes) -> danh sách số nguyên, mỗi khối một số."""
    block_bytes = pub.n // 8
    padded = pad(message, block_bytes)
    return [encrypt_block(bytes_to_bits(blk), pub)
            for blk in split_blocks(padded, block_bytes)]


def decrypt(cipher: List[int], priv: PrivateKey) -> bytes:
    """Danh sách số nguyên -> bản rõ (bytes), đã gỡ đệm."""
    block_bytes = priv.n // 8
    padded = b"".join(bits_to_bytes(decrypt_block(c, priv)) for c in cipher)
    return unpad(padded, block_bytes)


def encrypt_text(text: str, pub: PublicKey) -> List[int]:
    return encrypt(text.encode("utf-8"), pub)


def decrypt_text(cipher: List[int], priv: PrivateKey) -> str:
    return decrypt(cipher, priv).decode("utf-8")
