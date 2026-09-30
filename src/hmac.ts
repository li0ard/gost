import type { TArg, TRet } from "@noble/hashes/utils.js";
import { _HMAC } from "@noble/hashes/hmac.js";
import { streebog256, streebog512 } from "./streebog/index.js";
import { gost341194 } from "./gost341194/index.js";

/**
 * HMAC over Streebog-256 hash function
 * 
 * @param key - authentication key bytes
 */
export class Streebog256HMAC extends _HMAC<Streebog256HMAC> {
    constructor(key: TArg<Uint8Array>) {
        super(streebog256, key);
    }
}

/**
 * HMAC over Streebog-512 hash function
 * 
 * @param key - authentication key bytes
 */
export class Streebog512HMAC extends _HMAC<Streebog512HMAC> {
    constructor(key: TArg<Uint8Array>) {
        super(streebog512, key);
    }
}

/**
 * HMAC over GOST R 34.11-94 hash function
 * 
 * @param key - authentication key bytes
 */
export class Gost341194HMAC extends _HMAC<Gost341194HMAC> {
    constructor(key: TArg<Uint8Array>) {
        super(gost341194, key);
    }
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
 * ```
 */
export const streebog256hmac = (key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array> => 
    new Streebog256HMAC(key).update(message).digest();

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
 * ```
 */
export const streebog512hmac = (key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array> => 
    new Streebog512HMAC(key).update(message).digest();

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
 * ```
 */
export const gost341194hmac = (key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array> =>
    new Gost341194HMAC(key).update(message).digest();