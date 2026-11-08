import { streebog256hmac } from "./hmac.js";
import { numberToBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { streebog256, streebog512 } from "./streebog/index.js";
import { gost341194 } from "./gost341194/index.js";
import { xorBytesInPlace } from "./utils.js";
import { kdfInputToBytes, type KDFInput } from "@noble/hashes/utils.js";

const _0 = Uint8Array.of(0),
    _36 = new Uint8Array(64).fill(0x36),
    _6A = new Uint8Array(64).fill(0x6A); // 0x36 ^ 0x5C

/**
 * Key derivation function `KDF_GOSTR3411_2012_256`
 * @param key - derivation key.
 * @param label - parameter assigned by protocol.
 * @param seed - parameter assigned by protocol.
 * @returns Derived key bytes.
 */
export const kdf_gostr3411_2012_256 = (
    key: TArg<Uint8Array>,
    label: TArg<Uint8Array>,
    seed: TArg<Uint8Array>
): TRet<Uint8Array> => kdf_tree_gostr3411_2012_256(key, label, seed, 1)[0];

/** 
 * Key derivation function `KDF_TREE_GOSTR3411_2012_256`
 * 
 * @param key - derivation key.
 * @param label - parameter assigned by protocol.
 * @param seed - parameter assigned by protocol.
 * @param keys - desired derived key count.
 * @param i_len - number of bytes of counter (default - 1).
 * @returns Derived keys bytes.
 */
export const kdf_tree_gostr3411_2012_256 = (
    key: TArg<Uint8Array>,
    label: TArg<Uint8Array>,
    seed: TArg<Uint8Array>,
    keys: number,
    i_len: number = 1
): TRet<Uint8Array>[] => {
    const keymat = [],
        length = numberToBytesBE(keys * 32 * 8, 2);
    for(let i = 0; i < keys; i++) keymat.push(streebog256hmac.create(key)
        .update(numberToBytesBE(i + 1, i_len))
        .update(label).update(_0)
        .update(seed).update(length)
        .digest()
    );

    return keymat;
}

/**
 * PBKDF2 over Streebog-256
 * 
 * @param password - password from which a derived key is generated; JS string inputs are UTF-8 encoded first
 * @param salt - cryptographic salt; JS string inputs are UTF-8 encoded first
 * @param iter - iteration count. Higher values increase CPU cost.
 * @param dkLen - desired derived key length in bytes, must be `>= 1` per RFC 8018 §5.2.
 * @returns Derived key bytes.
 * @example
 * ```ts
 * import { streebog256pbkdf2 } from '@li0ard/gost/kdf.js';
 * const key = streebog256pbkdf2("password", "salt", 2, 32);
 * ```
 */
export const streebog256pbkdf2 = (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>,
    iter: number,
    dkLen: number
): TRet<Uint8Array> => pbkdf2(streebog256, password, salt, { dkLen, c: iter });

/**
 * PBKDF2 over Streebog-512
 * 
 * @param password - password from which a derived key is generated; JS string inputs are UTF-8 encoded first
 * @param salt - cryptographic salt; JS string inputs are UTF-8 encoded first
 * @param iter - iteration count. Higher values increase CPU cost.
 * @param dkLen - desired derived key length in bytes, must be `>= 1` per RFC 8018 §5.2.
 * @returns Derived key bytes.
 * @example
 * ```ts
 * import { streebog512pbkdf2 } from '@li0ard/gost/kdf.js';
 * const key = streebog512pbkdf2("password", "salt", 2, 64);
 * ```
 */
export const streebog512pbkdf2 = (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>,
    iter: number,
    dkLen: number
): TRet<Uint8Array> => pbkdf2(streebog512, password, salt, { dkLen, c: iter });

/**
 * PBKDF2 over GOST R 34.11-94
 * 
 * @param password - password from which a derived key is generated; JS string inputs are UTF-8 encoded first
 * @param salt - cryptographic salt; JS string inputs are UTF-8 encoded first
 * @param iter - iteration count. Higher values increase CPU cost.
 * @param dkLen - desired derived key length in bytes, must be `>= 1` per RFC 8018 §5.2.
 * @returns Derived key bytes.
 * @example
 * ```ts
 * import { gost341194pbkdf2 } from '@li0ard/gost/kdf.js';
 * const key = gost341194pbkdf2("password", "salt", 3, 32);
 * ```
 */
export const gost341194pbkdf2 = (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>,
    iter: number,
    dkLen: number
): TRet<Uint8Array> => pbkdf2(gost341194, password, salt, { dkLen, c: iter });

/**
 * CryptoPro key derivation function (CPKDF)
 * 
 * @param password - password from which a derived key is generated; JS string inputs are UTF-8 encoded first
 * @param salt - cryptographic salt; JS string inputs are UTF-8 encoded first
 * @returns Derived key bytes.
 * @example
 * ```ts
 * import { cpkdf } from '@li0ard/gost/kdf.js';
 * const key = cpkdf("password", "salt");
 * ```
 */
export const cpkdf = (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>
): TRet<Uint8Array> => {
    if(password.length > 256)
        throw new Error("Password cannot be longer than 256 symbols");
    const p = kdfInputToBytes(password),
        s = kdfInputToBytes(salt),
        hasPwd = p.length !== 0,
        pin = new Uint8Array(p.length * 4);
    for(let i = 0; i < p.length; i++) pin[i*4] = p[i];

    let hasher = streebog256.create();
    hasher.update(s);
    if(hasPwd) hasher.update(pin);
    const hash = hasher.digest();
    hasher = streebog256.create();

    const c = new Uint8Array(streebog256.blockLen);
    c.set(new TextEncoder().encode("DENEFH028.760246785.IUEFHWUIO.EF"));
    for(let j = 0; j < (hasPwd ? 2000 : 2); j++) {
        hasher = streebog256.create();
        xorBytesInPlace(c, _36);
        hasher.update(c).update(hash);
        xorBytesInPlace(c, _6A);
        hasher.update(c).update(hash);
        hasher.digestInto(c);
        c.fill(0, 32);
    }

    const cs = c.subarray(0, 32);
    hasher = streebog256.create();
    xorBytesInPlace(cs, _36);
    hasher.update(cs).update(s);
    xorBytesInPlace(cs, _6A);
    hasher.update(cs);
    if(hasPwd) hasher.update(pin);

    return streebog256(hasher.digest());
}