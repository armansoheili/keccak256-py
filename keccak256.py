"""Pure-Python implementation of Keccak-256 (the hash function Ethereum uses).

No dependencies — just the standard library. Great for learning how the
sponge construction and the Keccak-f[1600] permutation actually work.

Usage:
    from keccak256 import keccak_256, keccak_256_hex, keccak_256_file_hex

    keccak_256_hex(b"hello")   # -> 1c8aff950685c2ed4bc3172f34773b3a4b9a5b6a...
    keccak_256_file_hex("some_file.bin")  # hash a file
"""

MASK64 = 0xFFFFFFFFFFFFFFFF

# Keccak-f[1600] round constants (iota step)
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets r[x][y] for the rho step
ROT_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f1600(a):
    """Apply the Keccak-f[1600] permutation to a 25-lane state (in place)."""
    for rnd in range(24):
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            a[i] ^= d[i % 5]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(a[x + 5 * y], ROT_OFFSETS[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y] & MASK64) & b[(x + 2) % 5 + 5 * y]
                )
        # iota
        a[0] ^= RC[rnd]
    return a


def keccak_256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of data (32 bytes).

    Note: this is Keccak with the 0x01 domain suffix — the variant Ethereum
    uses — NOT NIST SHA3-256 (which uses 0x06).
    """
    block_size = 136  # rate = 1088 bits
    state = [0] * 25

    # pad10*1 with Keccak domain suffix 0x01
    suffix_len = 1
    zeros = (block_size - suffix_len - 1 - (len(data) % block_size)) % block_size
    padded = data + b"\x01" + b"\x00" * zeros + b"\x80"

    for off in range(0, len(padded), block_size):
        block = padded[off:off + block_size]
        for i in range(block_size // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)

    # squeeze 256 bits
    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out


def keccak_256_hex(data: bytes) -> str:
    return keccak_256(data).hex()


def keccak_256_file(path) -> bytes:
    """Keccak-256 digest of a file's contents (read in binary)."""
    with open(path, "rb") as f:
        return keccak_256(f.read())


def keccak_256_file_hex(path) -> str:
    return keccak_256_file(path).hex()


def selftest():
    vectors = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"hello ethereum": "b466f598d977fdbe7eea49ac6be9080b8f74f450c2f7ad3d42b98c54f9d07cc9",
        b"a" * 200: "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d",  # multi-block input
    }
    ok = True
    for data, want in vectors.items():
        got = keccak_256_hex(data)
        if got == want:
            print(f"OK   keccak256({data!r}) = {got}")
        else:
            ok = False
            print(f"FAIL keccak256({data!r})\n  got:  {got}\n  want: {want}")
    print("selftest:", "PASSED" if ok else "FAILED")
    return ok


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        raise SystemExit(0 if selftest() else 1)
    if len(sys.argv) == 3 and sys.argv[1] == "--file":
        print(keccak_256_file_hex(sys.argv[2]))
        raise SystemExit(0)
    msg = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "hello ethereum"
    print(keccak_256_hex(msg.encode()))
