"""EIP-55 checksum demo — shows why Keccak-256 matters on Ethereum.

EIP-55 encodes an Ethereum address with mixed-case hex so typos can be
caught: each letter is uppercased when the corresponding nibble of the
Keccak-256 hash of the lowercase address is >= 8.

Usage:
    python eip55.py 0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359
    python eip55.py --check 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5D359
"""

import sys

from keccak256 import keccak_256_hex


def checksum_address(address: str) -> str:
    addr = address.lower().removeprefix("0x")
    if len(addr) != 40 or any(c not in "0123456789abcdef" for c in addr):
        raise ValueError("not a 40-hex-char Ethereum address")
    digest = keccak_256_hex(addr.encode("ascii"))
    out = []
    for i, ch in enumerate(addr):
        if ch in "0123456789":
            out.append(ch)
        elif int(digest[i], 16) >= 8:
            out.append(ch.upper())
        else:
            out.append(ch)
    return "0x" + "".join(out)


def is_valid_checksum(address: str) -> bool:
    if not address.startswith(("0x", "0X")):
        return False
    try:
        return checksum_address(address) == address
    except ValueError:
        return False


def main(argv):
    if len(argv) == 2 and argv[0] == "--check":
        addr = argv[1]
        print(f"{addr} -> {'VALID checksum' if is_valid_checksum(addr) else 'INVALID checksum'}")
        return 0 if is_valid_checksum(addr) else 1
    if len(argv) != 1:
        print("usage: python eip55.py <address> | python eip55.py --check <address>")
        return 2
    try:
        print(checksum_address(argv[0]))
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
