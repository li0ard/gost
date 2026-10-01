/**
 * Implementation of GOST R 34.11-94 ([RFC 5831](https://datatracker.ietf.org/doc/html/rfc5831.html)) hash function
 * @module
 */
import { abytes, aoutput, clean, concatBytes, copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Magma } from "../magma/index.js";
import { ID_GOSTR_3411_94_CRYPTOPRO_PARAM_SET } from "../magma/const.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { xorBytes } from "../utils.js";

const r = (1n << 256n) - 1n;
const C3 = new Uint8Array([
    0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00
]);

const A = (x: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    xorBytes(x.subarray(24,32), x.subarray(16,24)),
    x.subarray(0,24)
);

const P = (x: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    x[31], x[23], x[15], x[7], x[30], x[22], x[14], x[6],
    x[29], x[21], x[13], x[5], x[28], x[20], x[12], x[4],
    x[27], x[19], x[11], x[3], x[26], x[18], x[10], x[2],
    x[25], x[17], x[9], x[1], x[24], x[16], x[8], x[0]
]);

const chi = (Y: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    Y[30] ^ Y[28] ^ Y[26] ^ Y[24] ^ Y[6] ^ Y[0],
    Y[31] ^ Y[29] ^ Y[27] ^ Y[25] ^ Y[7] ^ Y[1],
    ...Y.subarray(0,30)
]);

const _getMagma = (
    u: TArg<Uint8Array>,
    v: TArg<Uint8Array>,
    sbox: TArg<Uint8Array>
): Magma => new Magma(P(xorBytes(u, v)), sbox, true);

const _step = (
    hin: TArg<Uint8Array>,
    m: TArg<Uint8Array>,
    sbox: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const k1 = _getMagma(hin,m,sbox);

    let u = A(hin), v = A(A(m));
    const k2 = _getMagma(u,v,sbox);

    u = xorBytes(A(u), C3), v = A(A(v));
    const k3 = _getMagma(u,v,sbox);

    u = A(u), v = A(A(v));
    const k4 = _getMagma(u,v,sbox);

    const x = concatBytes(
        k4.encrypt(hin.slice(0,8).reverse()).reverse(),
        k3.encrypt(hin.slice(8,16).reverse()).reverse(),
        k2.encrypt(hin.slice(16,24).reverse()).reverse(),
        k1.encrypt(hin.slice(24,32).reverse()).reverse(),
    );
    for(let i = 0; i < 12; i++) x.set(chi(x));

    x.set(xorBytes(
        hin,
        chi(xorBytes(x, m))
    ));

    for(let i = 0; i < 61; i++) x.set(chi(x));

    return x;
}

/** Internal GOST R 34.11-94 hash class */
export class _Gost341194 implements Hash<_Gost341194> {
    readonly blockLen = 32;
    readonly outputLen = 32;
    readonly canXOF = false;
    private buffer = new Uint8Array(32);
    private pos = 0;
    private h = new Uint8Array(32);
    private len = 0n;
    private checksum = 0n;

    /** GOST R 34.11-94 hash function */
    constructor(
        private sbox: TArg<Uint8Array> = ID_GOSTR_3411_94_CRYPTOPRO_PARAM_SET
    ) {
        abytes(sbox, 64, "sbox");
    }

    /** Create hash instance */
    static create(): _Gost341194 { return new _Gost341194(); }

    destroy() {
        clean(this.buffer, this.h);
        this.pos = 0;
        this.len = 0n;
        this.checksum = 0n;
    }

    clone(): _Gost341194 { return this._cloneInto(); }
    _cloneInto(to?: _Gost341194): _Gost341194 {
        to ||= new _Gost341194(this.sbox);
        to.sbox = this.sbox;
        to.buffer.set(this.buffer);
        to.pos = this.pos;
        to.h.set(this.h);
        to.len = this.len;
        to.checksum = this.checksum;

        return to;
    }

    private processBlock(block: TArg<Uint8Array>) {
        const rev = copyBytes(block).reverse();
        this.len += 256n;
        this.checksum = (this.checksum + bytesToNumberBE(rev)) & r;
        this.h.set(_step(this.h, rev, this.sbox));
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
                this.processBlock(this.buffer);
                this.pos = 0;
            }
        }

        for (; offset + this.blockLen <= data.length; offset += this.blockLen)
            this.processBlock(data.subarray(offset, offset + this.blockLen));

        if (offset < data.length) {
            this.buffer.set(data.subarray(offset), 0);
            this.pos = data.length - offset;
        }

        return this;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aoutput(buf, this);
        if (this.pos > 0) {
            const part = new Uint8Array(this.blockLen);
            part.set(this.buffer.slice(0, this.pos).reverse(), this.blockLen - this.pos);
            this.len += BigInt(this.pos) * 8n;
            this.checksum = (this.checksum + bytesToNumberBE(part)) & r;
            this.h.set(_step(this.h, part, this.sbox));
        }

        const res = _step(
            _step(this.h, numberToBytesBE(this.len, this.blockLen), this.sbox),
            numberToBytesBE(this.checksum, this.blockLen),
            this.sbox
        );
        buf.set(res.reverse());
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
export const gost341194 = createHasher(_Gost341194.create);