<p align="center">
    <b>@li0ard/gost</b><br>
    <b>GOST cryptography algorithms in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/gost">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/gost/actions/workflows/test.yml"><img src="https://github.com/li0ard/gost/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/gost/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/gost" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/gost"><img src="https://img.shields.io/npm/v/@li0ard/gost" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
npm i @li0ard/gost
```

## Supported algorithms

- Curves and ECDSA (GOST R 34.10-2001 and GOST R 34.10-2012)
    - Determenistic signatures via [HMAC-DRBG (RFC 6979)](https://datatracker.ietf.org/doc/html/rfc6979) over Streebog-256 or Streebog-512
    - VKO key agreement function
    - Points conversion from Weierstrass to Twisted Edwards form and vice versa
    - Various curves included (TK-26, CryptoPro, tests etc.)
- GOST R 34.11-94 hash function
    - Supports HMAC and PBKDF2
- Kuznyechik cipher (GOST R 34.12-2015)
- Magma cipher (GOST R 34.12-2015)
    - Supports legacy version from GOST 28147-89
    - Various S-Box'es included (CryptoPro, DSSZZI, tests etc.)
- Streebog hash function (GOST R 34.11-2012)
    - Supports HMAC, PBKDF2, `kdf_gostr3411_2012_256`, `kdf_tree_gostr3411_2012_256` and CPKDF

## Supported cipher modes

- Cipher Block Chaining mode (CBC)
- Cipher Feedback mode (CFB)
- Counter mode (CTR)
    - Supports legacy version for GOST 28147-89 (CNT) and Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM)
- Electronic Codebook mode (ECB)
- Message Authentication Code mode (MAC)
    - Supports legacy version for GOST 28147-89 and MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM)
- Multilinear Galois mode (MGM)
- Output Feedback mode (OFB)
- Key wrapping:
    - Modern key wrapping with KExp15/KImp15
    - Legacy key wrapping for GOST 28147-89 (KWP) with CryptoPro key derivation