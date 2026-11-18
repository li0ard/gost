/**
 * Implementation of GOST R 34.11-2012 ([RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986.html)) "Streebog" hash function
 * @module
 */
import { aexists, aoutput, clean, createHasher, createView, type CHash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { A, C } from "./const.js";
import { PI } from "../kuznyechik/const.js";
import { HashMD } from "@noble/hashes/_md.js";

// Precompute Substitution+ Permutation + Linear transformations
const T = /* @__PURE__ */ (() => {
    const t = new Uint32Array(8 * 256 * 2);
    for (let c = 0; c < 8; c++) {
        for (let v = 0; v < 256; v++) {
            const s = PI[v];
            let hi = 0, lo = 0;
            for (let k = 0; k < 8; k++) {
                if ((s >> (7 - k)) & 1) {
                    hi ^= A[2 * (c * 8 + k)];
                    lo ^= A[2 * (c * 8 + k) + 1];
                }
            }
            const idx = ((c << 8) | v) << 1;
            t[idx] = hi;
            t[idx + 1] = lo;
        }
    }

    return t;
})();

const K = new Uint32Array(16),
    S = new Uint32Array(16),
    X = new Uint32Array(16),
    Y = new Uint32Array(16),
    M = new Uint32Array(16);

const LPS = (x: TArg<Uint32Array>, out: TArg<Uint32Array>) => {
    for (let o = 0; o < 2; o++) {
        const x0 = x[o], x1 = x[2 + o], x2 = x[4 + o], x3 = x[6 + o],
            x4 = x[8 + o], x5 = x[10 + o], x6 = x[12 + o], x7 = x[14 + o];

        for (let sh = 24, r = o << 2; sh >= 0; sh -= 8, r++) {
            let idx = ((0 << 8) | ((x0 >>> sh) & 0xff)) << 1; let hi = T[idx], lo = T[idx + 1];
            idx = ((1 << 8) | ((x1 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];
            idx = ((2 << 8) | ((x2 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];
            idx = ((3 << 8) | ((x3 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];
            idx = ((4 << 8) | ((x4 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];
            idx = ((5 << 8) | ((x5 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];
            idx = ((6 << 8) | ((x6 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];
            idx = ((7 << 8) | ((x7 >>> sh) & 0xff)) << 1; hi ^= T[idx]; lo ^= T[idx + 1];

            out[2 * r] = hi;
            out[2 * r + 1] = lo;
        }
    }
}

// h will be mutated
const G = (h: TArg<Uint32Array>, n: TArg<Uint32Array> | null, m: TArg<Uint32Array>) => {
    if (n) for (let i = 0; i < 16; i++) X[i] = n[i] ^ h[i];
    else X.set(h);
    LPS(X, K);

    for (let i = 0; i < 16; i++) S[i] = K[i] ^ m[i];
    for (let r = 0; r < 12; r++) {
        const off = r << 4;
        for (let i = 0; i < 16; i++) X[i] = K[i] ^ C[off + i];
        LPS(X, K);
        LPS(S, Y);
        for (let i = 0; i < 16; i++) S[i] = Y[i] ^ K[i];
    }
    for (let i = 0; i < 16; i++) h[i] ^= S[i] ^ m[i];
}

const add512 = (dst: TArg<Uint32Array>, src: TArg<Uint32Array>) => {
    let carry = 0;
    for (let i = 15; i >= 0; i--) {
        const s = dst[i] + src[i] + carry;
        dst[i] = s;
        carry = s > 0xffffffff ? 1 : 0;
    }
}

const addNum = (dst: TArg<Uint32Array>, x: number) => {
    let s = dst[15] + x;
    dst[15] = s;
    let carry = s > 0xffffffff ? 1 : 0;
    for (let i = 14; i >= 0 && carry; i--) {
        s = dst[i] + 1;
        dst[i] = s;
        carry = s > 0xffffffff ? 1 : 0;
    }
}

const loadBlock = (v: DataView, off: number = 0) => {
    for (let i = 0; i < 16; i++) M[i] = v.getUint32(off + ((15 - i) << 2), true);
}

/** Streebog (GOST R 34.11-2012) hash function */
class Streebog<T extends Streebog<T>> extends HashMD<T> {
    protected hash = new Uint32Array(16);
    protected n = new Uint32Array(16);
    protected sigma = new Uint32Array(16);

    constructor(is512: boolean) {
        super(64, is512 ? 64 : 32, 0, true);
        this.hash.fill(is512 ? 0 : 0x01010101);
    }

    protected process(view: DataView, off: number) {
        loadBlock(view, off);
        G(this.hash, this.n, M);
        addNum(this.n, 512);
        add512(this.sigma, M);
    }

    // Unused
    protected get(): number[] { return []; }
    protected set(...args: number[]) {}

    protected roundClean() {
        clean(K, S, X, Y, M);
    }

    override digestInto(out: TArg<Uint8Array>) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;
        this.buffer.fill(0, this.pos);
        this.buffer[this.pos] = 1;

        loadBlock(this.view);
        G(this.hash, this.n, M);
        addNum(this.n, this.pos * 8);
        add512(this.sigma, M);
        G(this.hash, null, this.n);
        G(this.hash, null, this.sigma);
        this.roundClean();

        const oview = out === this.buffer ? this.view : createView(out);
        for (let i = 0; i < (this.outputLen >> 2); i++)
            oview.setUint32(this.outputLen - 4 - (i << 2), this.hash[i], true);
    }

    destroy() {
        this.destroyed = true;
        clean(this.buffer, this.hash, this.n, this.sigma);
    }

    _cloneInto(to?: T): T {
        to ||= new (this.constructor as any)() as T;
        this._cloneIntoMeta(to);
        to.hash.set(this.hash);
        to.n.set(this.n);
        to.sigma.set(this.sigma);

        return to;
    }
}

/** Internal Streebog-256 hash class*/
export class _Streebog256 extends Streebog<_Streebog256> {
    constructor() { super(false); }
}

/** Internal Streebog-512 hash class*/
export class _Streebog512 extends Streebog<_Streebog512> {
    constructor() { super(true); }
}

/**
 * Streebog-256 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { streebog256 } from "@li0ard/gost/streebog.js";
 * 
 * streebog256(new Uint8Array([97, 98, 99]));
 * streebog256.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const streebog256: TRet<CHash<_Streebog256>> = /* @__PURE__ */ createHasher(
    () => new _Streebog256(),
    {
        oid: /* @__PURE__ */ Uint8Array.of(0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02)
    }
);
/**
 * Streebog-512 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { streebog512 } from "@li0ard/gost/streebog.js";
 * 
 * streebog512(new Uint8Array([97, 98, 99]));
 * streebog512.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const streebog512: TRet<CHash<_Streebog512>> = /* @__PURE__ */ createHasher(
    () => new _Streebog512(),
    {
        oid: /* @__PURE__ */ Uint8Array.of(0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03)
    }
);