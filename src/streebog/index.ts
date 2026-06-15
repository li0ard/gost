import { concatBytes, copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { A, C, TAU } from "./const.js";
import { PI } from "../kuznyechik/const.js";
import { pad1, xorBytes } from "../utils.js";
import { numberToBytesBE } from "@noble/curves/utils.js";

const BLOCKSIZE = 64;
const _0020 = new Uint8Array([0, 0, 2, 0]);
const _0 = new Uint8Array(64);

const add512 = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const c = new Uint8Array(64);
    const tmpA = new Uint8Array(64);
    const tmpB = new Uint8Array(64);

    for (let i = 0; i < a.length; i++) tmpA[63 - i] = a[a.length - i - 1];
    for (let i = 0; i < b.length; i++) tmpB[63 - i] = b[b.length - i - 1];
    for (let i = 63, tmp = 0; i >= 0; i--) {
        tmp = tmpA[i] + tmpB[i] + (tmp >> 8);
        c[i] = tmp & 0xff;
    }

    return c;
}

const S = (input: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    PI[input[0]], PI[input[1]], PI[input[2]], PI[input[3]], PI[input[4]], PI[input[5]],
    PI[input[6]], PI[input[7]], PI[input[8]], PI[input[9]], PI[input[10]], PI[input[11]],
    PI[input[12]], PI[input[13]], PI[input[14]], PI[input[15]], PI[input[16]], PI[input[17]],
    PI[input[18]], PI[input[19]], PI[input[20]], PI[input[21]], PI[input[22]], PI[input[23]],
    PI[input[24]], PI[input[25]], PI[input[26]], PI[input[27]], PI[input[28]], PI[input[29]],
    PI[input[30]], PI[input[31]], PI[input[32]], PI[input[33]], PI[input[34]], PI[input[35]],
    PI[input[36]], PI[input[37]], PI[input[38]], PI[input[39]], PI[input[40]], PI[input[41]],
    PI[input[42]], PI[input[43]], PI[input[44]], PI[input[45]], PI[input[46]], PI[input[47]],
    PI[input[48]], PI[input[49]], PI[input[50]], PI[input[51]], PI[input[52]], PI[input[53]],
    PI[input[54]], PI[input[55]], PI[input[56]], PI[input[57]], PI[input[58]], PI[input[59]],
    PI[input[60]], PI[input[61]], PI[input[62]], PI[input[63]]
]);

const P = (input: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    input[TAU[0]], input[TAU[1]], input[TAU[2]], input[TAU[3]], input[TAU[4]], input[TAU[5]],
    input[TAU[6]], input[TAU[7]], input[TAU[8]], input[TAU[9]], input[TAU[10]], input[TAU[11]],
    input[TAU[12]], input[TAU[13]], input[TAU[14]], input[TAU[15]], input[TAU[16]], input[TAU[17]],
    input[TAU[18]], input[TAU[19]], input[TAU[20]], input[TAU[21]], input[TAU[22]], input[TAU[23]],
    input[TAU[24]], input[TAU[25]], input[TAU[26]], input[TAU[27]], input[TAU[28]], input[TAU[29]],
    input[TAU[30]], input[TAU[31]], input[TAU[32]], input[TAU[33]], input[TAU[34]], input[TAU[35]],
    input[TAU[36]], input[TAU[37]], input[TAU[38]], input[TAU[39]], input[TAU[40]], input[TAU[41]],
    input[TAU[42]], input[TAU[43]], input[TAU[44]], input[TAU[45]], input[TAU[46]], input[TAU[47]],
    input[TAU[48]], input[TAU[49]], input[TAU[50]], input[TAU[51]], input[TAU[52]], input[TAU[53]],
    input[TAU[54]], input[TAU[55]], input[TAU[56]], input[TAU[57]], input[TAU[58]], input[TAU[59]],
    input[TAU[60]], input[TAU[61]], input[TAU[62]], input[TAU[63]]
]);

const L = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE);

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

        result.set(numberToBytesBE(parts[0], 4), i * 8);
        result.set(numberToBytesBE(parts[1], 4), i * 8 + 4);
    }

    return result;
}

const LPS = (input: TArg<Uint8Array>): TRet<Uint8Array> => L(P(S(input)));

const E = (block: TArg<Uint8Array>, keys: TArg<Uint8Array>): TRet<Uint8Array> => {
    // block will be mutated
    let c = xorBytes(block, keys);
    /*for (let i = 0; i < 12; i++) {
        block = LPS(xorBytes(block, C[i])); c = xorBytes(LPS(c), block);
    }*/
    block = LPS(xorBytes(block, C[0])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[1])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[2])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[3])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[4])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[5])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[6])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[7])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[8])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[9])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[10])); c = xorBytes(LPS(c), block);
    block = LPS(xorBytes(block, C[11])); c = xorBytes(LPS(c), block);

    return c;
}

const G = (
    hash: TArg<Uint8Array>,
    n: TArg<Uint8Array>,
    message: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(xorBytes(E(LPS(xorBytes(n, hash)), message), n), message);

/** Streebog (GOST R 34.11-2012) hash function */
abstract class Streebog<T extends Streebog<T>> implements Hash<Streebog<T>> {
    public readonly blockLen = BLOCKSIZE;
    public readonly outputLen: number;
    public readonly canXOF = false;
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
        const message = copyBytes(this.buffer).reverse();
        let n = new Uint8Array(this.blockLen);
        let sigma = new Uint8Array(this.blockLen);
        let hash = new Uint8Array(this.blockLen).fill(this.is512 ? 0 : 1);

        let blocks: number = 1;
        for (let i = message.length; i >= this.blockLen; i -= this.blockLen) {
            const pos: number = message.length - blocks * this.blockLen;

            hash = G(n, hash, message.subarray(pos, pos + this.blockLen));
            n = add512(n, _0020);
            sigma = add512(sigma, message.subarray(pos, pos + this.blockLen));
            blocks++;
        }

        let paddedMsg = new Uint8Array(this.blockLen);
        const msg = message.subarray(0, message.length - (blocks - 1) * 64);
        if (msg.length < this.blockLen) {
            paddedMsg = pad1(paddedMsg, this.blockLen);

            paddedMsg[this.blockLen - msg.length - 1] = 0x01;
            for (let i = 0; i < msg.length; i++) paddedMsg[this.blockLen - msg.length + i] = msg[i];
        }

        hash = G(
            _0,
            G(_0, G(n, hash, paddedMsg), add512(n, numberToBytesBE(msg.length * 8, 4))),
            add512(sigma, paddedMsg)
        );

        if (this.is512) buf.set(copyBytes(hash).reverse());
        else buf.set(hash.slice(0, 32).reverse());
        this.destroy();
    }
}

/** Streebog-256 (GOST R 34.11-2012) hash function */
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

/** Streebog-512 (GOST R 34.11-2012) hash function */
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

/** Streebog-256 (GOST R 34.11-2012) hash function */
export const streebog256 = createHasher(Streebog256.create);
/** Streebog-512 (GOST R 34.11-2012) hash function */
export const streebog512 = createHasher(Streebog512.create);