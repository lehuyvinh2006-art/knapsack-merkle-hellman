"""Giao diện dòng lệnh. Chỉ gọi các hàm của lõi, không chứa thuật toán.

Ví dụ:
    python cli.py keygen --n 64 --out key
    python cli.py encrypt --pub key.pub.json --text "Xin chào" --out msg.json
    python cli.py decrypt --priv key.priv.json --in msg.json
    python cli.py demo
"""
import argparse
import json
import sys

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
    p = argparse.ArgumentParser(description="Merkle–Hellman knapsack (chỉ dùng học tập)")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="tạo cặp khóa")
    k.add_argument("--n", type=int, default=64)
    k.add_argument("--out", default="key")

    e = sub.add_parser("encrypt", help="mã hóa văn bản")
    e.add_argument("--pub", required=True)
    e.add_argument("--text", required=True)
    e.add_argument("--out", default="cipher.json")

    d = sub.add_parser("decrypt", help="giải mã văn bản")
    d.add_argument("--priv", required=True)
    d.add_argument("--in", dest="inp", default="cipher.json")

    sub.add_parser("demo", help="chạy ví dụ minh họa")
    args = p.parse_args()

    try:
        if args.cmd == "keygen":
            pub, priv = generate_keys(args.n)
            save_keys(args.out, pub, priv)
            print(f"Đã tạo {args.out}.pub.json và {args.out}.priv.json (n = {args.n})")
        elif args.cmd == "encrypt":
            cipher = encrypt_text(args.text, load_pub(args.pub))
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump([str(c) for c in cipher], f, ensure_ascii=False, indent=2)
            print(f"Bản mã ({len(cipher)} khối) đã lưu vào {args.out}")
        elif args.cmd == "decrypt":
            # Đọc/kiểm tra JSON trước khi chuyển sang danh sách số nguyên.
            with open(args.inp, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("file bản mã phải chứa một danh sách JSON")

            cipher = []
            for index, value in enumerate(data):
                if type(value) is int:
                    number = value
                elif isinstance(value, str) and value.isdecimal():
                    number = int(value)
                else:
                    raise ValueError(f"khối bản mã thứ {index + 1} không phải số nguyên hợp lệ")
                if number < 0:
                    raise ValueError(f"khối bản mã thứ {index + 1} không được âm")
                cipher.append(number)

            print(decrypt_text(cipher, load_priv(args.priv)))
        elif args.cmd == "demo":
            pub, priv = generate_keys(64)
            text = "Hệ mã Knapsack Merkle–Hellman"
            cipher = encrypt_text(text, pub)
            print("Bản rõ  :", text)
            print("Bản mã  :", cipher)
            print("Giải mã :", decrypt_text(cipher, priv))
    except FileNotFoundError as exc:
        print(f"Lỗi: không tìm thấy file: {exc.filename}", file=sys.stderr)
        raise SystemExit(1) from None
    except json.JSONDecodeError as exc:
        print(f"Lỗi: JSON không hợp lệ (dòng {exc.lineno}, cột {exc.colno})", file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, TypeError, KeyError, ArithmeticError, IndexError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
