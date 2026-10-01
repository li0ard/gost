/**
 * Implementation of GOST R 34.11-2012 ([RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986.html)) "Streebog" hash function
 * @module
 */
import { abool, abytes, aoutput, clean, copyBytes, createHasher, createView, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { A, C } from "./const.js";
import { PI } from "../kuznyechik/const.js";
import { xorBytes } from "../utils.js";
import { numberToBytesBE } from "@noble/curves/utils.js";

const BLOCKSIZE = 64;
const _512 = new Uint8Array([0, 0, 2, 0]);

const add512Into = (dst: TArg<Uint8Array>, src: TArg<Uint8Array>): void => {
    const off = 64 - src.length;
    let carry = 0;
    for (let i = 63; i >= 0; i--) {
        const j = i - off;
        if (j < 0 && carry === 0) break;
        const s = dst[i] + (j >= 0 ? src[j] : 0) + carry;
        dst[i] = s & 0xff;
        carry = s >> 8;
    }
}

// Substitution + Permutation in 1 function
const SP = (input: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    PI[input[0]], PI[input[8]], PI[input[16]], PI[input[24]], PI[input[32]], PI[input[40]], PI[input[48]], PI[input[56]],
    PI[input[1]], PI[input[9]], PI[input[17]], PI[input[25]], PI[input[33]], PI[input[41]], PI[input[49]], PI[input[57]],
    PI[input[2]], PI[input[10]], PI[input[18]], PI[input[26]], PI[input[34]], PI[input[42]], PI[input[50]], PI[input[58]],
    PI[input[3]], PI[input[11]], PI[input[19]], PI[input[27]], PI[input[35]], PI[input[43]], PI[input[51]], PI[input[59]], 
    PI[input[4]], PI[input[12]], PI[input[20]], PI[input[28]], PI[input[36]], PI[input[44]], PI[input[52]], PI[input[60]],
    PI[input[5]], PI[input[13]], PI[input[21]], PI[input[29]], PI[input[37]], PI[input[45]], PI[input[53]], PI[input[61]],
    PI[input[6]], PI[input[14]], PI[input[22]], PI[input[30]], PI[input[38]], PI[input[46]], PI[input[54]], PI[input[62]],
    PI[input[7]], PI[input[15]], PI[input[23]], PI[input[31]], PI[input[39]], PI[input[47]], PI[input[55]], PI[input[63]]
]);

const L = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE), view = createView(result);
    for (let i = 0; i < 8; i++) {
        const parts = new Uint32Array(2);
        const tmp = input.slice(i * 8, i * 8 + 8).reverse();
        for (let j = 0; j < 8; j++) {
            for (let k = 0; k < 8; k++) {
                if ((tmp[7 - j] >> 7 - k) & 1) {
                    parts[0] ^= A[j * 16 + k * 2];
                    parts[1] ^= A[j * 16 + k * 2 + 1];
                }
            }
        }
        view.setUint32(i * 8, parts[0]);
        view.setUint32(i * 8 + 4, parts[1]);
    }

    return result;
}

const LPS = (input: TArg<Uint8Array>): TRet<Uint8Array> => L(SP(input));

const E = (block: TArg<Uint8Array>, keys: TArg<Uint8Array>): TRet<Uint8Array> => {
    // block will be mutated
    const c = xorBytes(block, keys);
    block.set(LPS(xorBytes(block, C.subarray(0, 64)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(64, 128)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(128, 192)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(192, 256)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(256, 320)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(320, 384)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(384, 448)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(448, 512)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(512, 576)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(576, 640)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(640, 704)))); c.set(xorBytes(LPS(c), block));
    block.set(LPS(xorBytes(block, C.subarray(704, 768)))); c.set(xorBytes(LPS(c), block));

    return c;
}

const G = (
    n: TArg<Uint8Array>,
    hash: TArg<Uint8Array>,
    message: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(xorBytes(E(LPS(xorBytes(n, hash)), message), hash), message);

const G2 = (
    hash: TArg<Uint8Array>,
    message: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(xorBytes(E(LPS(hash), message), hash), message);

/** Streebog (GOST R 34.11-2012) hash function */
abstract class Streebog<T extends Streebog<T>> implements Hash<Streebog<T>> {
    readonly blockLen = BLOCKSIZE;
    readonly outputLen: number;
    readonly canXOF = false;
    protected buffer = new Uint8Array(BLOCKSIZE);
    protected pos = 0;
    protected hash: Uint8Array;
    protected n: Uint8Array;
    protected sigma: Uint8Array;

    abstract _cloneInto(to?: T): T;
    abstract clone(): T;

    /** Streebog (GOST R 34.11-2012) hash function */
    constructor(private is512: boolean) {
        abool(is512);
        this.outputLen = is512 ? 64 : 32;
        this.hash = new Uint8Array(this.blockLen).fill(is512 ? 0 : 1);
        this.n = new Uint8Array(this.blockLen);
        this.sigma = new Uint8Array(this.blockLen);
    }

    destroy() {
        clean(this.buffer, this.n, this.sigma);
        this.hash.fill(this.is512 ? 0 : 1);
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

    private processBlock(block: TArg<Uint8Array>) {
        const rev = copyBytes(block).reverse();
        this.hash.set(G(this.n, this.hash, rev));
        add512Into(this.n, _512);
        add512Into(this.sigma, rev);
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

    digest(): TRet<Uint8Array> {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);
        return out;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aoutput(buf, this);
        const paddedMsg = new Uint8Array(this.blockLen);
        const offset = this.blockLen - this.pos;
        paddedMsg.set(this.buffer.slice(0, this.pos).reverse(), offset);
        paddedMsg[offset - 1] = 1;

        this.hash.set(G(this.n, this.hash, paddedMsg));
        add512Into(this.n, numberToBytesBE(this.pos * 8, 4));
        add512Into(this.sigma, paddedMsg);
        this.hash.set(G2(G2(this.hash, this.n), this.sigma));

        buf.set(this.hash.slice(0, this.outputLen).reverse());
        this.destroy();
    }
}

/** Streebog-256 hash function*/
export class Streebog256 extends Streebog<Streebog256> {
    /** Streebog-256 (GOST R 34.11-2012) hash function */
    constructor() { super(false); }

    /** Create hash instance */
    static create(): Streebog256 { return new Streebog256(); }

    clone(): Streebog256 { return this._cloneInto(); }
    _cloneInto(to?: Streebog256): Streebog256 {
        return this._copyState(to ||= new Streebog256());
    }
}

/** Streebog-512 hash function*/
export class Streebog512 extends Streebog<Streebog512> {
    /** Streebog-512 (GOST R 34.11-2012) hash function */
    constructor() { super(true); }

    /** Create hash instance */
    static create(): Streebog512 { return new Streebog512(); }

    clone(): Streebog512 { return this._cloneInto(); }
    _cloneInto(to?: Streebog512): Streebog512 {
        return this._copyState(to ||= new Streebog512());
    }
}

/** Streebog-256 hash function*/
export const streebog256 = createHasher(Streebog256.create);
/** Streebog-512 hash function*/
export const streebog512 = createHasher(Streebog512.create);