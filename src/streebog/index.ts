/**
 * Implementation of GOST R 34.11-2012 ([RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986.html)) "Streebog" hash function
 * @module
 */
import { abool, abytes, aoutput, clean, createHasher, createView, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { A, C } from "./const.js";
import { PI } from "../kuznyechik/const.js";

// Precompute Substitution+ Permutation + Linear transformations
let T: Uint32Array | undefined;

const initT = (): Uint32Array => {
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
    console.log("beep boop we generated");
    return t;
}

const K = new Uint32Array(16),
    S = new Uint32Array(16),
    X = new Uint32Array(16),
    Y = new Uint32Array(16),
    M = new Uint32Array(16);

const LPS = (x: Uint32Array, out: Uint32Array, t: Uint32Array) => {
    for (let r = 0; r < 8; r++) {
        const sh = 24 - ((r & 3) << 3);
        const o = r >> 2;
        let hi = 0, lo = 0, idx: number;

        idx = ((0 << 8) | ((x[0 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((1 << 8) | ((x[2 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((2 << 8) | ((x[4 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((3 << 8) | ((x[6 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((4 << 8) | ((x[8 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((5 << 8) | ((x[10 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((6 << 8) | ((x[12 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];
        idx = ((7 << 8) | ((x[14 + o] >>> sh) & 0xff)) << 1; hi ^= t[idx]; lo ^= t[idx + 1];

        out[2 * r] = hi;
        out[2 * r + 1] = lo;
    }
}

// h will be mutated
const G = (h: Uint32Array, n: Uint32Array | null, m: Uint32Array) => {
    const t = (T ||= initT());
    if (n) for (let i = 0; i < 16; i++) X[i] = n[i] ^ h[i];
    else X.set(h);
    LPS(X, K, t);

    for (let i = 0; i < 16; i++) S[i] = K[i] ^ m[i];

    for (let r = 0; r < 12; r++) {
        const off = r << 4;
        for (let i = 0; i < 16; i++) X[i] = K[i] ^ C[off + i];
        LPS(X, K, t);
        LPS(S, Y, t);
        for (let i = 0; i < 16; i++) S[i] = Y[i] ^ K[i];
    }

    for (let i = 0; i < 16; i++) h[i] ^= S[i] ^ m[i];
}

const add512 = (dst: Uint32Array, src: Uint32Array) => {
    let carry = 0;
    for (let i = 15; i >= 0; i--) {
        const s = dst[i] + src[i] + carry;
        dst[i] = s;
        carry = s > 0xffffffff ? 1 : 0;
    }
}

const addNum = (dst: Uint32Array, x: number) => {
    let s = dst[15] + x;
    dst[15] = s;
    let carry = s > 0xffffffff ? 1 : 0;
    for (let i = 14; i >= 0 && carry; i--) {
        s = dst[i] + 1;
        dst[i] = s;
        carry = s > 0xffffffff ? 1 : 0;
    }
}

const loadBlock = (v: DataView, off: number, out: Uint32Array) => {
    for (let i = 0; i < 16; i++) out[i] = v.getUint32(off + ((15 - i) << 2), true);
}

/** Streebog (GOST R 34.11-2012) hash function */
abstract class Streebog<T extends Streebog<T>> implements Hash<Streebog<T>> {
    readonly blockLen = 64;
    readonly outputLen: number;
    readonly canXOF = false;
    protected buffer = new Uint8Array(this.blockLen);
    protected bufView = createView(this.buffer);
    protected pos = 0;
    protected hash = new Uint32Array(16);
    protected n = new Uint32Array(16);
    protected sigma = new Uint32Array(16);

    /** Streebog (GOST R 34.11-2012) hash function */
    constructor(private is512: boolean) {
        abool(is512);
        this.outputLen = is512 ? 64 : 32;
        this.hash.fill(is512 ? 0 : 0x01010101);
    }

    destroy() {
        clean(this.buffer, this.n, this.sigma);
        this.hash.fill(this.is512 ? 0 : 0x01010101);
        this.pos = 0;
    }

    protected _copyState(to: T): T {
        to.buffer.set(this.buffer);
        to.pos = this.pos;
        to.hash.set(this.hash);
        to.n.set(this.n);
        to.sigma.set(this.sigma);
        return to;
    }

    abstract _cloneInto(to?: Streebog<T>): Streebog<T>;
    abstract clone(): Streebog<T>;

    private processBlock(v: DataView, off: number) {
        loadBlock(v, off, M);
        G(this.hash, this.n, M);
        addNum(this.n, 512);
        add512(this.sigma, M);
    }

    update(data: TArg<Uint8Array>): this {
        abytes(data);
        const view = createView(data);
        let offset = 0;
        if (this.pos > 0) {
            const take = Math.min(this.blockLen - this.pos, data.length);
            this.buffer.set(data.subarray(0, take), this.pos);
            this.pos += take;
            offset = take;
            if (this.pos === this.blockLen) {
                this.processBlock(this.bufView, 0);
                this.pos = 0;
            }
        }

        for (; offset + this.blockLen <= data.length; offset += this.blockLen)
            this.processBlock(view, offset);

        if (offset < data.length) {
            this.buffer.set(data.subarray(offset), 0);
            this.pos = data.length - offset;
        }

        return this;
    }

    digest(): TRet<Uint8Array> {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);
        return out;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aoutput(buf, this);
        this.buffer.fill(0, this.pos);
        this.buffer[this.pos] = 1;
        loadBlock(this.bufView, 0, M);

        G(this.hash, this.n, M);
        addNum(this.n, this.pos * 8);
        add512(this.sigma, M);
        G(this.hash, null, this.n);
        G(this.hash, null, this.sigma);

        const out = createView(buf);
        const words = this.outputLen >> 2;
        for (let i = 0; i < words; i++)
            out.setUint32(this.outputLen - 4 - (i << 2), this.hash[i], true);

        this.destroy();
    }
}

/** Internal Streebog-256 hash class*/
export class _Streebog256 extends Streebog<_Streebog256> {
    /** Streebog-256 (GOST R 34.11-2012) hash function */
    constructor() { super(false); }

    /** Create hash instance */
    static create(): _Streebog256 { return new _Streebog256(); }

    _cloneInto(to?: _Streebog256): _Streebog256 {
        return this._copyState(to ||= new _Streebog256());
    }
    clone(): _Streebog256 { return this._cloneInto(); }
}

/** Internal Streebog-512 hash class*/
export class _Streebog512 extends Streebog<_Streebog512> {
    /** Streebog-512 (GOST R 34.11-2012) hash function */
    constructor() { super(true); }

    /** Create hash instance */
    static create(): _Streebog512 { return new _Streebog512(); }

    _cloneInto(to?: _Streebog512): _Streebog512 {
        return this._copyState(to ||= new _Streebog512());
    }
    clone(): _Streebog512 { return this._cloneInto(); }
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
export const streebog256 = /* @__PURE__ */ createHasher(_Streebog256.create);
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
export const streebog512 = /* @__PURE__ */ createHasher(_Streebog512.create);