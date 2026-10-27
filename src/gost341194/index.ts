/**
 * Implementation of GOST R 34.11-94 ([RFC 5831](https://datatracker.ietf.org/doc/html/rfc5831.html)) hash function
 * @module
 */
import { abytes, aoutput, clean, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { GOSTR_3411_94_CRYPTOPRO_PARAM_SET } from "../magma/const.js";
import { numberToBytesBE } from "@noble/curves/utils.js";

const C3 = new Uint8Array([
    0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00
]);

const initT = (sbox: TArg<Uint8Array>): TRet<Int32Array> => {
    const t = new Int32Array(4 * 256);
    const s = (i: number, n: number): number => {
        const b = sbox[i * 8 + (n >> 1)];
        return (n & 1) === 0 ? b >>> 4 : b & 0x0f;
    }

    for (let j = 0; j < 4; j++) {
        for (let b = 0; b < 256; b++) {
            const x = (s(2 * j, b & 0x0f) << (8 * j)) | (s(2 * j + 1, b >> 4) << (8 * j + 4));
            t[j * 256 + b] = (x << 11) | (x >>> 21);
        }
    }

    return t;
}

const TABLES = new WeakMap<Uint8Array, Int32Array>();
const getTables = (sbox: TArg<Uint8Array>): Int32Array => {
    let t = TABLES.get(sbox);
    if (!t) TABLES.set(sbox, t = initT(sbox));
    return t;
}

const U = new Uint8Array(32),
    V = new Uint8Array(32),
    X = new Uint8Array(32),
    M = new Uint8Array(32),
    TMP = new Uint8Array(8),
    KEYS = new Int32Array(32),
    Q = new Uint8Array(160),
    Q16 = new Uint16Array(Q.buffer);

const A = (x: Uint8Array) => {
    for (let i = 0; i < 8; i++) TMP[i] = x[24 + i] ^ x[16 + i];
    x.copyWithin(8, 0, 24);
    x.set(TMP);
}

const psi = (y: Uint8Array, n: number) => {
    for (let i = 0; i < 32; i++) Q[i] = y[31 - i];
    for (let k = 0; k < n; k++)
        Q16[k + 16] = Q16[k] ^ Q16[k + 1] ^ Q16[k + 2] ^ Q16[k + 3] ^ Q16[k + 12] ^ Q16[k + 15];
    const base = 2 * n + 31;
    for (let i = 0; i < 32; i++) y[i] = Q[base - i];
}

const setKey = (idx: number, u: Uint8Array, v: Uint8Array) => {
    const o = idx << 3;
    for (let j = 0; j < 8; j++) {
        KEYS[o + j] =
            (u[31 - j] ^ v[31 - j]) |
            ((u[23 - j] ^ v[23 - j]) << 8) |
            ((u[15 - j] ^ v[15 - j]) << 16) |
            ((u[7 - j] ^ v[7 - j]) << 24);
    }
}

const f = (x: number, T: Int32Array): number =>
    T[x & 0xff] ^ T[256 + ((x >>> 8) & 0xff)] ^ T[512 + ((x >>> 16) & 0xff)] ^ T[768 + (x >>> 24)];

const enc = (h: Uint8Array, off: number, ko: number, T: Int32Array) => {
    let a0 = (h[off] << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3],
        a1 = (h[off + 4] << 24) | (h[off + 5] << 16) | (h[off + 6] << 8) | h[off + 7],
        t = 0;
    for (let r = 0; r < 24; r++) {
        t = a1;
        a1 = a0 ^ f((a1 + KEYS[ko + (r & 7)]) | 0, T);
        a0 = t;
    }
    for (let j = 7; j >= 0; j--) {
        t = a1;
        a1 = a0 ^ f((a1 + KEYS[ko + j]) | 0, T);
        a0 = t;
    }

    X[off] = a1 >>> 24;
    X[off + 1] = a1 >>> 16;
    X[off + 2] = a1 >>> 8;
    X[off + 3] = a1;
    X[off + 4] = a0 >>> 24;
    X[off + 5] = a0 >>> 16;
    X[off + 6] = a0 >>> 8;
    X[off + 7] = a0;
}

const step = (h: Uint8Array, m: TArg<Uint8Array>, T: Int32Array) => {
    U.set(h);
    V.set(m);
    setKey(0, U, V);

    A(U); A(V); A(V);
    setKey(1, U, V);

    A(U);
    for (let i = 0; i < 32; i++) U[i] ^= C3[i];
    A(V); A(V);
    setKey(2, U, V);

    A(U); A(V); A(V);
    setKey(3, U, V);

    enc(h, 0, 24, T); // k4
    enc(h, 8, 16, T); // k3
    enc(h, 16, 8, T); // k2
    enc(h, 24, 0, T); // k1

    psi(X, 12);
    for (let i = 0; i < 32; i++) X[i] ^= m[i];
    psi(X, 1);
    for (let i = 0; i < 32; i++) X[i] ^= h[i];
    psi(X, 61);

    h.set(X);
}

const addLE = (acc: Uint8Array, src: TArg<Uint8Array>, off: number, len: number) => {
    let c = 0;
    for (let i = 0; i < 32; i++) {
        const s = acc[i] + (i < len ? src[off + i] : 0) + c;
        acc[i] = s;
        c = s >> 8;
    }
}

/** Internal GOST R 34.11-94 hash class */
export class _Gost341194 implements Hash<_Gost341194> {
    readonly blockLen = 32;
    readonly outputLen = 32;
    readonly canXOF = false;
    private buffer = new Uint8Array(32);
    private pos = 0;
    private h = new Uint8Array(32);
    private checksum = new Uint8Array(32);
    private bytes = 0;
    private tables?: Int32Array;

    /** Internal GOST R 34.11-94 hash class */
    constructor(
        private sbox: TArg<Uint8Array> = GOSTR_3411_94_CRYPTOPRO_PARAM_SET
    ) {
        abytes(sbox, 64, "sbox");
    }

    /** Create hash instance */
    static create(): _Gost341194 { return new _Gost341194(); }

    destroy() {
        clean(this.buffer, this.h, this.checksum);
        this.pos = 0;
        this.bytes = 0;
    }

    clone(): _Gost341194 { return this._cloneInto(); }
    _cloneInto(to?: _Gost341194): _Gost341194 {
        to ||= new _Gost341194(this.sbox);
        to.sbox = this.sbox;
        to.tables = this.tables;
        to.buffer.set(this.buffer);
        to.pos = this.pos;
        to.h.set(this.h);
        to.checksum.set(this.checksum);
        to.bytes = this.bytes;

        return to;
    }

    private processBlock(src: TArg<Uint8Array>, off: number) {
        const T = (this.tables ||= getTables(this.sbox));
        for (let i = 0; i < 32; i++) M[i] = src[off + 31 - i];
        addLE(this.checksum, src, off, 32);
        this.bytes += 32;
        step(this.h, M, T);
    }

    update(data: TArg<Uint8Array>): this {
        abytes(data);
        let offset = 0;
        if (this.pos > 0) {
            const take = Math.min(this.blockLen - this.pos, data.length);
            this.buffer.set(data.subarray(0, take), this.pos);
            this.pos += take;
            offset = take;
            if (this.pos === this.blockLen) {
                this.processBlock(this.buffer, 0);
                this.pos = 0;
            }
        }

        for (; offset + this.blockLen <= data.length; offset += this.blockLen)
            this.processBlock(data, offset);

        if (offset < data.length) {
            this.buffer.set(data.subarray(offset));
            this.pos = data.length - offset;
        }

        return this;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aoutput(buf, this);
        const T = (this.tables ||= getTables(this.sbox));
        if (this.pos > 0) {
            this.buffer.fill(0, this.pos);
            for (let i = 0; i < 32; i++) M[i] = this.buffer[31 - i];
            addLE(this.checksum, this.buffer, 0, 32);
            this.bytes += this.pos;
            step(this.h, M, T);
        }

        step(this.h, numberToBytesBE(BigInt(this.bytes) * 8n, 32), T);

        for (let i = 0; i < 32; i++) M[i] = this.checksum[31 - i];
        step(this.h, M, T);

        for (let i = 0; i < 32; i++) buf[i] = this.h[31 - i];

        clean(U, V, X, M, KEYS);
        this.destroy();
    }

    digest(): TRet<Uint8Array> {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);

        return out;
    }
}

/**
 * GOST R 34.11-94 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { gost341194 } from "@li0ard/gost/gost341194.js";
 * 
 * gost341194(new Uint8Array([97, 98, 99]));
 * gost341194.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const gost341194 = /* @__PURE__ */ createHasher(_Gost341194.create);