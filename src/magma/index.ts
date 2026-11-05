/**
 * Implementation of GOST R 34.12-2015 ([RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html)) and GOST 28147-89 ([RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830.html))
 * "Magma" block ciphers
 * 
 * Differences between GOST R 34.12-2015 and GOST 28147-89:
 * - GOST R 34.12-2015 uses fixed S-Box (`TC26_GOST_28147_PARAM_Z`)
 * - GOST R 34.12-2015 uses BE byte order (instead of LE in GOST 28147-89)
 * @module
 */
import { abool, abytes, createView, type TArg, type TRet } from "@noble/hashes/utils.js";
import { GOST_28147_89_CRYPTO_PRO_A_PARAM_SET, TC26_GOST_28147_PARAM_Z, magmaKeySequences } from "./const.js";
import type { Cipher } from "../types.js";

const nibble = (sbox: TArg<Uint8Array>, r: number, i: number): number => {
    const b = sbox[(r << 3) + (i >> 1)];
    return (i & 1) === 0 ? (b >>> 4) : (b & 0x0f);
}

const genTable = (sbox: TArg<Uint8Array>): TRet<Uint32Array> => {
    const table = new Uint32Array(4 * 256);
    for (let k = 0; k < 4; k++) {
        for (let v = 0; v < 256; v++) {
            const x = ((nibble(sbox, 2 * k + 1, v >> 4) << 4) | nibble(sbox, 2 * k, v & 15)) << (8 * k);
            table[(k << 8) | v] = (x << 11) | (x >>> 21);
        }
    }
    return table;
}

const TABLES = new WeakMap<Uint8Array, Uint32Array>();
const getTable = (sbox: TArg<Uint8Array>): TRet<Uint32Array> => {
    let t = TABLES.get(sbox);
    if (!t) TABLES.set(sbox, t = genTable(sbox));
    return t as TRet<Uint32Array>;
}

const G = (v: number, t: TArg<Uint32Array>): number =>
    t[v & 0xff] ^ t[256 + ((v >>> 8) & 0xff)] ^
    t[512 + ((v >>> 16) & 0xff)] ^ t[768 + (v >>> 24)];

/** Magma (GOST R 34.12-2015 and GOST 28147-89) cipher */
export class Magma implements Cipher {
    readonly keySize = 32;
    readonly blockSize = 8;

    private rk = new Uint32Array(8);

    /**
     * Magma (GOST R 34.12-2015 and GOST 28147-89) cipher
     * 
     * @param key - encryption key
     * @param sbox - S-Box
     * @param isLegacy - whether to use GOST 28147-89 instead of GOST R 34.12-2015
     */
    constructor(
        key: TArg<Uint8Array>,
        private sbox: TArg<Uint8Array> = TC26_GOST_28147_PARAM_Z,
        public isLegacy: boolean = false
    ) {
        abytes(key, this.keySize, "key");
        abytes(sbox, 64, "sbox");
        abool(isLegacy, "isLegacy");

        const view = createView(key);
        for (let i = 0; i < 8; i++) this.rk[i] = view.getUint32(i * 4, isLegacy);
    }

    proceedBlock(block: TArg<Uint8Array>, sequence: ArrayLike<number>): TRet<Uint8Array> {
        abytes(block, this.blockSize, "block");

        const inView = createView(block),
            t = getTable(this.sbox);
        let a0 = inView.getUint32(this.isLegacy ? 4 : 0, this.isLegacy),
            a1 = inView.getUint32(this.isLegacy ? 0 : 4, this.isLegacy);
        for (let i = 0; i < sequence.length; i++) {
            const temp = a1;
            a1 = (a0 ^ G((a1 + this.rk[sequence[i]]) >>> 0, t)) >>> 0;
            a0 = temp;
        }

        const out = new Uint8Array(this.blockSize),
            outView = createView(out);
        if (this.isLegacy) {
            outView.setUint32(0, a0, true);
            outView.setUint32(4, a1, true);
        } else {
            outView.setUint32(0, a1);
            outView.setUint32(4, a0);
        }

        return out;
    }

    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(plaintext, magmaKeySequences.ENCRYPT);
    }

    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(ciphertext, magmaKeySequences.DECRYPT);
    }
}

/** Shortcut for Magma (legacy variation) cipher */
export class MagmaLegacy extends Magma {
    /** Shortcut for Magma (legacy variation) cipher */
    constructor(
        key: TArg<Uint8Array>,
        sbox: TArg<Uint8Array> = GOST_28147_89_CRYPTO_PRO_A_PARAM_SET
    ) {
        super(key, sbox, true);
    }
}

export { magmaSboxes, magmaKeySequences } from "./const.js";