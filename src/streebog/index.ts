/**
 * Implementation of GOST R 34.11-2012 ([RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986.html)) "Streebog" hash function
 * @module
 */
import { concatBytes, copyBytes, createHasher, createView, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { A, C } from "./const.js";
import { PI } from "../kuznyechik/const.js";
import { xorBytes } from "../utils.js";
import { numberToBytesBE } from "@noble/curves/utils.js";

const BLOCKSIZE = 64;
const _512 = new Uint8Array([0, 0, 2, 0]);
const _0 = new Uint8Array(64);

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
    hash: TArg<Uint8Array>,
    n: TArg<Uint8Array>,
    message: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(xorBytes(E(LPS(xorBytes(n, hash)), message), n), message);

const G2 = (
    n: TArg<Uint8Array>,
    message: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(xorBytes(E(LPS(n), message), n), message);

/** Streebog (GOST R 34.11-2012) hash function */
abstract class Streebog<T extends Streebog<T>> implements Hash<Streebog<T>> {
    readonly blockLen = BLOCKSIZE;
    readonly outputLen: number;
    readonly canXOF = false;
    protected buffer: Uint8Array;

    abstract _cloneInto(to?: T): T;
    abstract clone(): T;

    /** Streebog (GOST R 34.11-2012) hash function */
    constructor(private is512: boolean) {
        this.buffer = new Uint8Array();
        this.outputLen = is512 ? 64 : 32;
    }

    destroy() { this.buffer = new Uint8Array(); }

    update(data: TArg<Uint8Array>): this {
        this.buffer = concatBytes(this.buffer, data);
        return this;
    }

    digest(): TRet<Uint8Array> { 
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);

        return buffer;
    }

    digestInto(buf: TArg<Uint8Array>) {
        if(buf.length != this.outputLen) throw new Error("digestInto: Invalid buffer length");
        const message = copyBytes(this.buffer).reverse();
        const n = new Uint8Array(this.blockLen),
            sigma = new Uint8Array(this.blockLen),
            hash = new Uint8Array(this.blockLen).fill(this.is512 ? 0 : 1);

        let blocks: number = 1;
        for (let i = message.length; i >= this.blockLen; i -= this.blockLen) {
            const pos: number = message.length - blocks * this.blockLen;

            const block = message.subarray(pos, pos + this.blockLen);
            hash.set(G(n, hash, block));
            add512Into(n, _512);
            add512Into(sigma, block);
            blocks++;
        }

        const paddedMsg = new Uint8Array(this.blockLen);
        const msg = message.subarray(0, message.length - (blocks - 1) * 64);
        if (msg.length < this.blockLen) {
            const offset = this.blockLen - msg.length;
            paddedMsg[offset - 1] = 1;
            paddedMsg.set(msg, offset);
        }

        hash.set(G(n, hash, paddedMsg));
        add512Into(n, numberToBytesBE(msg.length * 8, 4));
        add512Into(sigma, paddedMsg);
        hash.set(G2(G2(hash, n), sigma));

        buf.set(hash.slice(0, this.outputLen).reverse());
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
        to ||= new Streebog256();
        to.buffer = new Uint8Array(this.buffer);

        return to;
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
        to ||= new Streebog512();
        to.buffer = new Uint8Array(this.buffer);

        return to;
    }
}

/** Streebog-256 hash function*/
export const streebog256 = createHasher(Streebog256.create);
/** Streebog-512 hash function*/
export const streebog512 = createHasher(Streebog512.create);