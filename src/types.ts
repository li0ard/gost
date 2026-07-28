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

/** GOST R 34.10 signer */
export type Signer = {
    getPublicKey: (secretKey: TArg<Uint8Array>, isCompressed?: boolean) => TRet<Uint8Array>;
    sign: (secretKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, rand?: TArg<Uint8Array>) => TRet<Uint8Array>;
    verify: (publicKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, signature: TArg<Uint8Array>) => boolean;
    keygen: Keygen;
    getSharedSecret: (hash: CHash, secretKeyA: TArg<Uint8Array>, publicKeyB: TArg<Uint8Array>, ukm: TArg<Uint8Array>) => TRet<Uint8Array>;
    Point: WeierstrassPointCons<bigint>;
    utils: {
        uv2xy: (point: AffinePoint<bigint>) => AffinePoint<bigint>;
        xy2uv: (point: AffinePoint<bigint>) => AffinePoint<bigint>;
        swapPoint: (point: TArg<Uint8Array>) => TRet<Uint8Array>;
        parameters: GostCurveParameters;
    }
}