# keccak256-py

A pure-Python implementation of **Keccak-256** — the hash function Ethereum uses for
addresses, transaction IDs, contract storage slots, and more. Zero dependencies,
just the standard library.

> Note: this is Keccak with the `0x01` domain suffix (the Ethereum variant),
> **not** NIST SHA3-256 (which uses `0x06`). They produce different digests.

## Files

- `keccak256.py` — the implementation (`keccak_256`, `keccak_256_hex`), plus a CLI and self-test
- `eip55.py` — demo: EIP-55 checksummed Ethereum address encoder / validator

## Quick start

```bash
# hash something
python keccak256.py "hello ethereum"

# run the built-in test vectors
python keccak256.py --selftest

# checksum an address (EIP-55)
python eip55.py 0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359
# -> 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359

# validate a checksummed address
python eip55.py --check 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359
```

## How it works

Keccak is a *sponge construction* built on the `Keccak-f[1600]` permutation:
25 lanes of 64 bits, transformed over 24 rounds of θ (theta), ρ (rho), π (pi),
χ (chi), and ι (iota). Input is absorbed in 136-byte blocks (`pad10*1`
padding), then 256 bits are squeezed out as the digest.
