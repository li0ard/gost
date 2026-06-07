import { bytesToNumberBE, concatBytes, copyBytes, numberToBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";
import { ID_TC26_GOST_28147_PARAM_Z, magmaKeySequences } from "./const.js";
import type { Cipher } from "../types.js";

const BLOCKSIZE = 8, KEYSIZE = 32;

const T = (value: number, sbox: TArg<Uint8Array>[]): number => (
    (sbox[0][(value >> 0) & 0x0f] << 0) |
    (sbox[1][(value >> 4) & 0x0f] << 4) |
    (sbox[2][(value >> 8) & 0x0f] << 8) |
    (sbox[3][(value >> 12) & 0x0f] << 12) |
    (sbox[4][(value >> 16) & 0x0f] << 16) |
    (sbox[5][(value >> 20) & 0x0f] << 20) |
    (sbox[6][(value >> 24) & 0x0f] << 24) |
    (sbox[7][(value >> 28) & 0x0f] << 28)
) >>> 0;

const G = (a: number, k: number, sbox: TArg<Uint8Array>[]): number => {
    const substituted = T((a + k) >>> 0, sbox);
    return ((substituted << 11) | (substituted >>> 21)) >>> 0;
}

/** Magma (GOST R 34.12-2015 and GOST 28147-89) cipher */
export class Magma implements Cipher {
    public readonly keySize = KEYSIZE;
    public readonly blockSize = BLOCKSIZE;

    private key: TArg<Uint8Array>;
    /**
     * Magma (GOST R 34.12-2015 and GOST 28147-89) cipher
     * @param key Encryption key
     * @param sbox S-Box
     * @param isLegacy Use GOST 28147-89 instead of GOST R 34.12-2015?
     */
    constructor(
        key: TArg<Uint8Array>,
        private sbox: TArg<Uint8Array>[] = ID_TC26_GOST_28147_PARAM_Z,
        public isLegacy: boolean = false
    ) {
        if (key.length !== this.keySize) throw new Error("Invalid key length");
        this.key = isLegacy ? Magma.reverseKey(key) : key;
    }

    private regenerateRoundKeys(sequence: number[]): number[] {
        const keyChunks: number[] = [];
        for (let j = 0; j < 8; j++)
            keyChunks.push(Number(bytesToNumberBE(this.key.subarray(j * 4, j * 4 + 4))));

        const roundKeys = new Array(sequence.length);
        for (let i = 0; i < sequence.length; i++)
            roundKeys[i] = keyChunks[sequence[i]];

        return roundKeys;
    }

    public proceedBlock(block: TArg<Uint8Array>, sequence: number[]): TRet<Uint8Array> {
        if (block.length !== this.blockSize) throw new Error("Invalid block size");
        const roundKeys = this.regenerateRoundKeys(sequence);

        let a0 = Number(bytesToNumberBE(block.subarray(0, 4)));
        let a1 = Number(bytesToNumberBE(block.subarray(4, 8)));
        for (let i = 0; i < roundKeys.length; i++) {
            const temp = a1;
            a1 = (a0 ^ G(a1, roundKeys[i], this.sbox)) >>> 0;
            a0 = temp;
        }

        return concatBytes(numberToBytesBE(a1, 4), numberToBytesBE(a0, 4));
    }

    public encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        if(this.isLegacy)
            return Magma.reverseChunks(this.proceedBlock(Magma.reverseChunks(plaintext), magmaKeySequences.ENCRYPT));
        return this.proceedBlock(plaintext, magmaKeySequences.ENCRYPT);
    }

    public decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        if(this.isLegacy)
            return Magma.reverseChunks(this.proceedBlock(Magma.reverseChunks(ciphertext), magmaKeySequences.DECRYPT));
        return this.proceedBlock(ciphertext, magmaKeySequences.DECRYPT);
    }

    static reverseKey(key: TArg<Uint8Array>): TRet<Uint8Array> {
        const result = new Uint8Array(KEYSIZE);
        for (let i = 0; i < BLOCKSIZE; i++)
            result.set(copyBytes(key.subarray(i * 4, i * 4 + 4)).reverse(), i * 4);
        return result;
    }

    static reverseChunks(data: TArg<Uint8Array>): TRet<Uint8Array> {
        const chunks = [];
        for (let i = 0; i < data.length; i += BLOCKSIZE)
            chunks.push(copyBytes(data.subarray(i, i + BLOCKSIZE)).reverse());

        return concatBytes(...chunks);
    }
}

export { magmaSboxes, magmaKeySequences } from "./const.js";