/**
 * Implementation of GOST R 34.12-2015 ([RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html)) and GOST 28147-89 ([RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830.html))
 * "Magma" block ciphers
 * 
 * Differences between GOST R 34.12-2015 and GOST 28147-89:
 * - GOST R 34.12-2015 uses fixed S-Box (`ID_TC26_GOST_28147_PARAM_Z`)
 * - GOST R 34.12-2015 uses BE byte order (instead of LE in GOST 28147-89)
 * @module
 */
import { bytesToNumberBE, bytesToNumberLE, concatBytes, numberToBytesBE, numberToBytesLE, type TArg, type TRet } from "@noble/curves/utils.js";
import { ID_TC26_GOST_28147_PARAM_Z, magmaKeySequences } from "./const.js";
import type { Cipher } from "../types.js";
import { createView } from "@noble/hashes/utils.js";

const BLOCKSIZE = 8;

const G = (v: number, sbox: TArg<Uint8Array>): number => {
    const t = (sbox[(v & 0x0f)] << 0) |
        (sbox[16 + ((v >> 4) & 0x0f)] << 4) |
        (sbox[32 + ((v >> 8) & 0x0f)] << 8) |
        (sbox[48 + ((v >> 12) & 0x0f)] << 12) |
        (sbox[64 + ((v >> 16) & 0x0f)] << 16) |
        (sbox[80 + ((v >> 20) & 0x0f)] << 20) |
        (sbox[96 + ((v >> 24) & 0x0f)] << 24) |
        (sbox[112 + ((v >> 28) & 0x0f)] << 28);
    return ((t << 11) | (t >>> 21)) >>> 0;
}

const extendKey = (key: TArg<Uint8Array>, sequence: number[], isLegacy: boolean): TRet<Uint32Array> => {
    const view = createView(key);
    const chunks = new Uint32Array(BLOCKSIZE);
    for (let i = 0; i < BLOCKSIZE; i++) chunks[i] = view.getUint32(i * 4, isLegacy);

    return new Uint32Array(sequence.map(i => chunks[i]));
}

/** Magma (GOST R 34.12-2015 and GOST 28147-89) cipher */
export class Magma implements Cipher {
    public readonly keySize = 32;
    public readonly blockSize = BLOCKSIZE;

    /**
     * Magma (GOST R 34.12-2015 and GOST 28147-89) cipher
     * @param key Encryption key
     * @param sbox S-Box
     * @param isLegacy Use GOST 28147-89 instead of GOST R 34.12-2015?
     */
    constructor(
        private key: TArg<Uint8Array>,
        private sbox: TArg<Uint8Array> = ID_TC26_GOST_28147_PARAM_Z,
        public isLegacy: boolean = false
    ) {
        if (key.length !== this.keySize) throw new Error("Invalid key length");
    }

    public proceedBlock(block: TArg<Uint8Array>, sequence: number[]): TRet<Uint8Array> {
        if (block.length !== this.blockSize) throw new Error("Invalid block size");
        const roundKeys = extendKey(this.key, sequence, this.isLegacy);

        const F = block.subarray(0, 4), S = block.subarray(4, 8);
        const bytesToNumber = this.isLegacy ? bytesToNumberLE : bytesToNumberBE;
        
        let a0 = Number(bytesToNumber(this.isLegacy ? S : F)),
            a1 = Number(bytesToNumber(this.isLegacy ? F : S));
        for (let i = 0; i < roundKeys.length; i++) {
            const temp = a1;
            a1 = (a0 ^ G((a1 + roundKeys[i]) >>> 0, this.sbox)) >>> 0;
            a0 = temp;
        }

        if (this.isLegacy) return concatBytes(numberToBytesLE(a0, 4), numberToBytesLE(a1, 4));
        else return concatBytes(numberToBytesBE(a1, 4), numberToBytesBE(a0, 4));
    }

    public encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(plaintext, magmaKeySequences.ENCRYPT);
    }

    public decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(ciphertext, magmaKeySequences.DECRYPT);
    }
}

export { magmaSboxes, magmaKeySequences } from "./const.js";