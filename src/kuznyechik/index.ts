/**
 * Implementation of GOST R 34.12-2015 ([RFC 7801](https://datatracker.ietf.org/doc/html/rfc7801.html)) "Kuznyechik" block cipher
 * @module
 */
import { abytes, copyBytes, swap32IfBE, u32, u8, type TArg, type TRet } from "@noble/hashes/utils.js";
import { ITER, L as L_, PI, PI_REV } from "./const.js";
import type { Cipher } from "../types.js";
import { gf256Multiply } from "../gf/index.js";

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

const LR = (input: TArg<Uint8Array>) => {
    let p = 0;
    for (let n = 0; n < 16; n++) {
        let c = 0;
        for (let k = 0; k < 16; k++)
            c ^= gf256Multiply(input[(p + k) & 15], L_[k]);
        input[p] = c;
        p = (p + 1) & 15;
    }
}

const genTable = (sbox: TArg<Uint8Array>, fn: (x: TArg<Uint8Array>) => void) => {
    const table = new Uint32Array(16 * 256 * 4),
        b = new Uint8Array(16),
        w = u32(b);
    for (let i = 0; i < 16; i++) {
        for (let v = 0; v < 256; v++) {
            b.fill(0);
            b[i] = sbox[v];
            fn(b);
            table.set(w, ((i << 8) | v) << 2);
        }
    }

    return swap32IfBE(table);
}

const ID = Uint8Array.from({ length: 256 }, (_, i) => i),
    T_ENC = genTable(PI, L),
    T_DEC = genTable(PI_REV, LR),
    T_LINV = genTable(ID, LR);

const lookup = (table: TArg<Uint32Array>, s: TArg<Uint32Array>) => {
    let a = 0, b = 0, c = 0, d = 0;
    for (let i = 0; i < 16; i++) {
        const j = ((i << 8) | ((s[i >> 2] >>> ((i & 3) << 3)) & 0xff)) << 2;
        a ^= table[j]; b ^= table[j + 1];
        c ^= table[j + 2]; d ^= table[j + 3];
    }
    s[0] = a; s[1] = b;
    s[2] = c; s[3] = d;
}

const C = swap32IfBE(u32(ITER).slice());

const xor4 = (s: TArg<Uint32Array>, k: TArg<Uint32Array>, o = 0) => {
    s[0] ^= k[o]; s[1] ^= k[o + 1];
    s[2] ^= k[o + 2]; s[3] ^= k[o + 3];
}

export class Kuznyechik implements Cipher {
    readonly keySize = 32;
    readonly blockSize = 16;

    private rk = new Uint32Array(40);
    private rkInv = new Uint32Array(40);
    private k0: Uint8Array;

    constructor(key: TArg<Uint8Array>) {
        abytes(key, this.keySize, "key");
        u8(this.rk).set(key);
        swap32IfBE(this.rk.subarray(0, 8));
        this.k0 = key.slice(0, 16);

        let a = this.rk.slice(0, 4),
            b = this.rk.slice(4, 8),
            t = new Uint32Array(4);
        for (let i = 0; i < 4; i++) {
            for (let j = 0; j < 8; j++) {
                const o = (i * 8 + j) * 4;
                t[0] = a[0] ^ C[o]; t[1] = a[1] ^ C[o + 1];
                t[2] = a[2] ^ C[o + 2]; t[3] = a[3] ^ C[o + 3];
                lookup(T_ENC, t);
                xor4(t, b);
                const old = b; b = a;
                a = t; t = old;
            }
            this.rk.set(a, 8 + 8 * i);
            this.rk.set(b, 12 + 8 * i);
        }

        for (let r = 1; r <= 8; r++) {
            t.set(this.rk.subarray(r * 4, r * 4 + 4));
            lookup(T_LINV, t);
            this.rkInv.set(t, r * 4);
        }
    }

    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(plaintext, this.blockSize, "plaintext");
        const out = copyBytes(plaintext),
            s = swap32IfBE(u32(out));
        for (let r = 0; r < 9; r++) {
            xor4(s, this.rk, r * 4);
            lookup(T_ENC, s);
        }
        xor4(s, this.rk, 36);
        swap32IfBE(s);

        return out;
    }

    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(ciphertext, this.blockSize, "ciphertext");
        const out = copyBytes(ciphertext),
            s = swap32IfBE(u32(out));
        xor4(s, this.rk, 36);
        lookup(T_LINV, s);
        for (let r = 8; r >= 1; r--) {
            lookup(T_DEC, s);
            xor4(s, this.rkInv, r * 4);
        }
        swap32IfBE(s);
        for (let i = 0; i < 16; i++) out[i] = PI_REV[out[i]] ^ this.k0[i];

        return out;
    }
}