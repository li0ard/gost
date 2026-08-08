import type { AffinePoint, WeierstrassPointCons } from "@noble/curves/abstract/weierstrass.js";
import type { CHash, TArg, TRet } from "@noble/hashes/utils.js";
import type { GostCurveParameters } from "./gost3410/index.js";

export type CipherOrHashFunctionWrapper = (msg: TArg<Uint8Array>) => TRet<Uint8Array>;

/** Cipher core */
export type Cipher = {
    /** Block size */
    readonly blockSize: number;
    /** Key size */
    readonly keySize: number;
    /** Encrypt block */
    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array>;
    /** Decrypt block */
    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array>;
}

/** Block mode for {@link Cipher} */
export type BlockMode = {
    /** Encrypt plaintext */
    encrypt: (plaintext: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Decrypt ciphertext */
    decrypt: (ciphertext: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Stream-like mode for {@link Cipher} */
export type StreamMode = {
    /** Proceed message */
    crypt: CipherOrHashFunctionWrapper;
}

/** MAC mode for {@link Cipher} */
export type MACMode = {
    /** Compute MAC */
    compute: CipherOrHashFunctionWrapper;
}

/** AEAD mode for {@link Cipher} */
export type AEADMode = {
    /** Seal plaintext and AAD */
    seal: (plaintext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Open ciphertext and AAD */
    open: (ciphertext: TArg<Uint8Array>, aad?: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Key wrapping mode for {@link Cipher} */
export type WrapMode = {
    /** Wrap encryption key */
    wrap: (key: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Unwrap encryption key */
    unwrap: (wrapped: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Key wrapping mode (KWP) for Magma */
export type WrapModeMagma = {
    /** Wrap encryption key */
    wrap: (ukm: TArg<Uint8Array>, cek: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Unwrap encryption key */
    unwrap: (wrapped: TArg<Uint8Array>) => TRet<Uint8Array>;
}

/** Keypair generator */
export type Keygen = (seed?: TArg<Uint8Array>, isCompressed?: boolean) => {
    secretKey: TRet<Uint8Array>;
    publicKey: TRet<Uint8Array>;
}

/** 
 * - `extraEntropy` - Creates signatures with increased security (Adding randomness to deterministic generator)
 * - `rand` - Specify custom ephemeral key **(DO NOT USE IN PRODUCTION)**
 */
export type SignOpts = {
    rand?: TArg<Uint8Array>;
    extraEntropy?: boolean;
}

/** GOST R 34.10 signer */
export type Signer = {
    /**
     * Computes public key for a secret key. Checks for validity of the secret key.
     * @param isCompressed - whether to return compact (default), or full key
     * @returns Public key, full when `isCompressed=false`; short when `isCompressed=true`
     */
    getPublicKey: (secretKey: TArg<Uint8Array>, isCompressed?: boolean) => TRet<Uint8Array>;
    /**
     * Signs a message hash with a secret key.
     * 
     * ```
     * sign(d, m) where
     *   e = m mod n (if e=0, let e=1)
     *   k = streebog_hmac_drbg(d, m)
     *   (x, y) = G × k
     *   r = x mod n
     *   s = (r ⋅ d + k ⋅ e) mod n
     * ```
     */
    sign: (secretKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, opts?: SignOpts) => TRet<Uint8Array>;
    /**
     * Verifies a signature against message hash and public key.
     * 
     * ```
     * verify(P, m, r, s) where
     *   e = m mod n (if e=0, let e=1)
     *   v = e^-1 mod n
     *   z1 = s ⋅ v mod n
     *   z2 = -r ⋅ v mod n
     *   R = (z1 × G + z2 × P).x mod n
     *   R == r
     * ```
     */
    verify: (publicKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, signature: TArg<Uint8Array>) => boolean;
    /** Keypair generator */
    keygen: Keygen;
    /**
     * Key agreement function (ECDH)
     * 
     * Computes hashed shared point from secret key A and public key B.
     * @param hash Hash function to use (GOST R 34.11-94, Streebog-256, Streebog-512)
     * @param ukm User keying material (aka salt, VKO-factor)
     */
    getSharedSecret: (hash: CHash, secretKeyA: TArg<Uint8Array>, publicKeyB: TArg<Uint8Array>, ukm: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Constructor and metadata helpers for Weierstrass points */
    Point: WeierstrassPointCons<bigint>;
    /** Utils */
    utils: {
        /** Convert point from Twisted Edwards to Weierstrass (if supported) */
        uv2xy: (point: AffinePoint<bigint>) => AffinePoint<bigint>;
        /** Convert point from Weierstrass to Twisted Edwards (if supported) */
        xy2uv: (point: AffinePoint<bigint>) => AffinePoint<bigint>;
        /** Swap `x` and `y` in uncompressed point bytes (or `r` and `s` in signature) */
        swapPoint: (point: TArg<Uint8Array>) => TRet<Uint8Array>;
        /** Curve parameters passed to `gost3410` constructor */
        parameters: GostCurveParameters;
    }
}