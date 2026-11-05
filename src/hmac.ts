import type { CHash, Hash, TArg, TRet } from "@noble/hashes/utils.js";
import { type _HMAC, hmac } from "@noble/hashes/hmac.js";
import { streebog256, streebog512 } from "./streebog/index.js";
import { gost341194 } from "./gost341194/index.js";

type CHmac<T extends Hash<T>> = {
    (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array>;
    readonly outputLen: number;
    readonly blockLen: number;
    readonly canXOF: boolean;
    create(key: TArg<Uint8Array>): _HMAC<T>;
}

const createHmac = <T extends Hash<T>>(hash: CHash<T>): CHmac<T> => {
    const hmacC = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>) =>
        hmac(hash, key, msg);
    
    hmacC.outputLen = hash.outputLen;
    hmacC.blockLen = hash.blockLen;
    hmacC.canXOF = false;
    hmacC.create = (key: TArg<Uint8Array>) => hmac.create(hash, key);

    return Object.freeze(hmacC);
}

/**
 * HMAC over Streebog-256 hash function
 * 
 * @param key - authentication key bytes
 * @param message - message bytes to authenticate
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { streebog256hmac } from "@li0ard/gost/hmac.js";
 * const key = new Uint8Array([1, 2, 3]);
 * const message = new Uint8Array([4, 5, 6]);
 * const mac = streebog256hmac(key, message);
 * const mac2 = streebog256hmac.create(key).update(message).digest();
 * ```
 */
export const streebog256hmac = createHmac(streebog256);
/**
 * HMAC over Streebog-512 hash function
 * 
 * @param key - authentication key bytes
 * @param message - message bytes to authenticate
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { streebog512hmac } from "@li0ard/gost/hmac.js";
 * const key = new Uint8Array([1, 2, 3]);
 * const message = new Uint8Array([4, 5, 6]);
 * const mac = streebog512hmac(key, message);
 * const mac2 = streebog512hmac.create(key).update(message).digest();
 * ```
 */
export const streebog512hmac = createHmac(streebog512);

/**
 * HMAC over GOST R 34.11-94 hash function
 * 
 * @param key - authentication key bytes
 * @param message - message bytes to authenticate
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { gost341194hmac } from "@li0ard/gost/hmac.js";
 * const key = new Uint8Array([1, 2, 3]);
 * const message = new Uint8Array([4, 5, 6]);
 * const mac = gost341194hmac(key, message);
 * const mac2 = gost341194hmac.create(key).update(message).digest();
 * ```
 */
export const gost341194hmac = createHmac(gost341194);