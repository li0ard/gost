import { type TArg, type TRet } from "@noble/hashes/utils.js";
import { _HMAC } from "@noble/hashes/hmac.js";
import { streebog256, streebog512 } from "./streebog/index.js";
import { gost341194 } from "./gost341194/index.js";

/** HMAC over Streebog-256 hash function */
export class Streebog256HMAC extends _HMAC<Streebog256HMAC> {
    constructor(key: TArg<Uint8Array>) {
        super(streebog256, key);
    }
}

/** HMAC over Streebog-512 hash function */
export class Streebog512HMAC extends _HMAC<Streebog512HMAC> {
    constructor(key: TArg<Uint8Array>) {
        super(streebog512, key);
    }
}

/** HMAC over GOST R 34.11-94 hash function */
export class Gost341194HMAC extends _HMAC<Gost341194HMAC> {
    constructor(key: TArg<Uint8Array>) {
        super(gost341194, key);
    }
}

/** HMAC over Streebog-256 hash function */
export const streebog256hmac = (key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array> => 
    new Streebog256HMAC(key).update(message).digest();

/** HMAC over Streebog-512 hash function */
export const streebog512hmac = (key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array> => 
    new Streebog512HMAC(key).update(message).digest();

/** HMAC over GOST R 34.11-94 hash function */
export const gost341194hmac = (key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array> =>
    new Gost341194HMAC(key).update(message).digest();