"""Giao diện dòng lệnh. Chỉ gọi các hàm của lõi, không chứa thuật toán.

Ví dụ:
    python cli.py keygen --n 64 --out key
    python cli.py encrypt --pub key.pub.json --text "Xin chào" --out msg.json
    python cli.py decrypt --priv key.priv.json --in msg.json
    python cli.py demo
"""
import argparse
import json

from cipher import decrypt_text, encrypt_text
from knapsack_core import PrivateKey, PublicKey, generate_keys


def save_keys(prefix: str, pub: PublicKey, priv: PrivateKey) -> None:
    with open(prefix + ".pub.json", "w") as f:
        json.dump({"B": [str(b) for b in pub.B]}, f)
    with open(prefix + ".priv.json", "w") as f:
        json.dump({"W": [str(w) for w in priv.W], "q": str(priv.q),
                   "r": str(priv.r), "r_inv": str(priv.r_inv)}, f)


def load_pub(path: str) -> PublicKey:
    with open(path) as f:
        return PublicKey([int(b) for b in json.load(f)["B"]])


def load_priv(path: str) -> PrivateKey:
    with open(path) as f:
        d = json.load(f)
    return PrivateKey([int(w) for w in d["W"]], int(d["q"]),
                      int(d["r"]), int(d["r_inv"]))


def main() -> None:
    p = argparse.ArgumentParser(description="Merkle–Hellman knapsack")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("--n", type=int, default=64)
    k.add_argument("--out", default="key")

    e = sub.add_parser("encrypt")
    e.add_argument("--pub", required=True)
    e.add_argument("--text", required=True)
    e.add_argument("--out", default="cipher.json")

    d = sub.add_parser("decrypt")
    d.add_argument("--priv", required=True)
    d.add_argument("--in", dest="inp", default="cipher.json")

    sub.add_parser("demo")
    args = p.parse_args()

    if args.cmd == "keygen":
        pub, priv = generate_keys(args.n)
        save_keys(args.out, pub, priv)
        print(f"Đã tạo {args.out}.pub.json và {args.out}.priv.json (n = {args.n})")
    elif args.cmd == "encrypt":
        cipher = encrypt_text(args.text, load_pub(args.pub))
        with open(args.out, "w") as f:
            json.dump([str(c) for c in cipher], f)
        print(f"Bản mã ({len(cipher)} khối) đã lưu vào {args.out}")
    elif args.cmd == "decrypt":
        with open(args.inp) as f:
            cipher = [int(c) for c in json.load(f)]
        print(decrypt_text(cipher, load_priv(args.priv)))
    elif args.cmd == "demo":
        pub, priv = generate_keys(64)
        text = "Hệ mã Knapsack Merkle–Hellman"
        cipher = encrypt_text(text, pub)
        print("Bản rõ  :", text)
        print("Bản mã  :", cipher)
        print("Giải mã :", decrypt_text(cipher, priv))


if __name__ == "__main__":
    main()
