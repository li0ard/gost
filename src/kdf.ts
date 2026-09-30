import { streebog256hmac } from "./hmac.js";
import { numberToBytesBE, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { streebog256, streebog512 } from "./streebog/index.js";
import { gost341194 } from "./gost341194/index.js";
import { xorBytes } from "./utils.js";
import { kdfInputToBytes, type KDFInput } from "@noble/hashes/utils.js";

const _0 = new Uint8Array([0]);
const _1 = new Uint8Array([1]);
const _256 = new Uint8Array([1,0]);
const _36 = new Uint8Array(64).fill(0x36);
const _5C = new Uint8Array(64).fill(0x5C);

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
): TRet<Uint8Array> => streebog256hmac(
    key,
    concatBytes(_1, label, _0, seed, _256)
);

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
    const keymat = [];
    const length = numberToBytesBE(keys * 32 * 8, 2);

    for(let i = 0; i < keys; i++)
        keymat.push(streebog256hmac(key, concatBytes(
            numberToBytesBE(i + 1, i_len),
            label,
            _0,
            seed,
            length
        )));

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
 * @throws If the PBKDF2 iteration count or derived-key settings are invalid. {@link Error}
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
 * @throws If the PBKDF2 iteration count or derived-key settings are invalid. {@link Error}
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
 * @throws If the PBKDF2 iteration count or derived-key settings are invalid. {@link Error}
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
    const hasher = streebog256.create();
    const bs = streebog256.blockLen;
    const p = kdfInputToBytes(password), s = kdfInputToBytes(salt);
    if(password.length > 256)
        throw new Error("Password cannot be longer than 256 symbols");

    const pin = new Uint8Array(password.length * 4);
    for(let i = 0; i < password.length; i++) pin[i*4] = p[i];

    hasher.update(s);
    if(password.length != 0) hasher.update(pin);
    const hash = hasher.digest();

    const c = new Uint8Array(bs);
    c.set(new TextEncoder().encode("DENEFH028.760246785.IUEFHWUIO.EF"));
    const m0 = new Uint8Array(bs), m1 = new Uint8Array(bs);
    for(let j = 0; j < (password.length != 0 ? 2000 : 2); j++) {
        m0.set(xorBytes(c, _36));
        m1.set(xorBytes(c, _5C));
        hasher.update(m0).update(hash).update(m1).update(hash);
        c.set(hasher.digest());
        c.fill(0, 32);
    }

    m0.set(xorBytes(c, _36));
    m1.set(xorBytes(c, _5C));
    hasher.update(m0.subarray(0, 32)).update(s).update(m1.subarray(0, 32));
    if(password.length != 0) hasher.update(pin);
    hasher.update(hasher.digest());

    return hasher.digest();
}