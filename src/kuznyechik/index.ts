/**
 * Implementation of GOST R 34.12-2015 ([RFC 7801](https://datatracker.ietf.org/doc/html/rfc7801.html)) "Kuznyechik" block cipher
 * @module
 */
import { abytes, copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { ITER, L as L_, PI, PI_REV } from "./const.js";
import { xorBytesInPlace } from "../utils.js";
import type { Cipher } from "../types.js";
import { gf256Multiply } from "../gf/index.js";

const S = (input: TArg<Uint8Array>, pi: TArg<Uint8Array> = PI) => {
    for (let i = 0; i < 16; i++) input[i] = pi[input[i]];
}

const L = (input: TArg<Uint8Array>) => {
    let p = 0;
    for (let n = 0; n < 16; n++) {
        let c = 0;
        for (let k = 0; k < 16; k++)
            c ^= gf256Multiply(input[(p + k) & 15], L_[(k + 1) & 15]);
        p = (p + 15) & 15;
        input[p] = c;
    }
}

const Lr = (input: TArg<Uint8Array>) => {
    let p = 0;
    for (let n = 0; n < 16; n++) {
        let c = 0;
        for (let k = 0; k < 16; k++)
            c ^= gf256Multiply(input[(p + k) & 15], L_[k]);
        input[p] = c;
        p = (p + 1) & 15;
    }
}

const SL = (input: TArg<Uint8Array>) => {
    S(input);
    L(input);
}

/** Kuznyechik (GOST R 34.12-2015) cipher */
export class Kuznyechik implements Cipher {
    readonly keySize = 32;
    readonly blockSize = 16;

    private roundKeys: Uint8Array[];
    /**
     * Kuznyechik (GOST R 34.12-2015) cipher
     * 
     * @param key - encryption key
     */
    constructor(key: TArg<Uint8Array>) {
        abytes(key, this.keySize, "key");

        const roundKeys = Array<Uint8Array>(10);
        roundKeys[0] = key.slice(0, 16);
        roundKeys[1] = key.slice(16);

        let a = copyBytes(roundKeys[0]),
            b = copyBytes(roundKeys[1]),
            t = new Uint8Array(16);
        for (let i = 0; i < 4; i++) {
            for (let j = 0; j < 8; j++) {
                const o = (i * 8 + j) * 16;
                t.set(a);
                xorBytesInPlace(t, ITER, o);
                SL(t);
                xorBytesInPlace(t, b);
                const old = b; b = a; a = t; t = old;
            }
            roundKeys[2 + 2 * i] = copyBytes(a);
            roundKeys[3 + 2 * i] = copyBytes(b);
        }
        this.roundKeys = roundKeys;
    }

    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(plaintext, this.blockSize, "plaintext");
        const s = copyBytes(plaintext);
        for (let r = 0; r < 9; r++) {
            xorBytesInPlace(s, this.roundKeys[r]);
            SL(s);
        }
        xorBytesInPlace(s, this.roundKeys[9]);
        return s;
    }

    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(ciphertext, this.blockSize, "ciphertext");
        const s = copyBytes(ciphertext);
        xorBytesInPlace(s, this.roundKeys[9]);
        for (let r = 8; r >= 0; r--) {
            Lr(s);
            S(s, PI_REV);
            xorBytesInPlace(s, this.roundKeys[r]);
        }
        return s;
    }
}