import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, MACMode } from "../types.js";
import { pad1, pad3, xorBytes } from "../utils.js";
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE, numberToVarBytesBE } from "@noble/curves/utils.js";
import { magmaKeySequences, Magma } from "../magma/index.js";
import { acpkm_master } from "./_keytransform.js";

const Rb64 = 0b11011;
const Rb128 = 0b10000111;

const shift1 = (src: TArg<Uint8Array>, dst: TArg<Uint8Array>): number => {
    let b = 0;
    for(let i = src.length - 1; i >= 0; i--) {
        const bb = src[i] >> 7;
		dst[i] = src[i]<<1 | b;
		b = bb;
    }

    return b;
}

/**
 * **EN:** Message Authentication Code (MAC) mode
 * 
 * **RU:** Режим выработки имитовставки
 */
export const mac = (cipher: Cipher): MACMode => {
    const encrypter = cipher.encrypt.bind(cipher);
    const Rb = cipher.blockSize === 16 ? Rb128 : Rb64;
    const L = encrypter(new Uint8Array(cipher.blockSize));

    return {
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const k1 = new Uint8Array(cipher.blockSize);
            const msb = shift1(L, k1);
            if (msb) k1[cipher.blockSize - 1] ^= Rb;

            const k2 = new Uint8Array(cipher.blockSize);
            const msb2 = shift1(k1, k2);
            if (msb2) k2[cipher.blockSize - 1] ^= Rb;

            const n = Math.ceil(msg.length / cipher.blockSize) || 1;
            const lastBlockComplete = msg.length > 0 && msg.length % cipher.blockSize === 0;

            let buf = new Uint8Array(cipher.blockSize);
            for (let i = 0; i < n - 1; i++) {
                const m = msg.subarray(i * cipher.blockSize, (i + 1) * cipher.blockSize);
                buf = encrypter(xorBytes(buf, m));
            }

            let lastBlock: Uint8Array;
            if (lastBlockComplete && msg.length > 0) lastBlock = xorBytes(
                msg.subarray((n - 1) * cipher.blockSize, n * cipher.blockSize),
                k1
            );
            else {
                const padded = new Uint8Array(cipher.blockSize);
                const remaining = msg.length - (n - 1) * cipher.blockSize;
                padded.set(msg.subarray((n - 1) * cipher.blockSize));
                padded[remaining] = 0x80;
                lastBlock = xorBytes(padded, k2);
            }

            return encrypter(xorBytes(buf, lastBlock));
        }
    }
}

/**
 * **EN:** Message Authentication Code (MAC) mode (GOST 28147-89)
 * 
 * **RU:** Режим выработки имитовставки (ГОСТ 28147-89)
 */
export const mac_legacy = (cipher: Magma, iv: TArg<Uint8Array> = new Uint8Array(cipher.blockSize)): MACMode => {
    const split = (data: TArg<Uint8Array>): number[] => [
        Number(bytesToNumberLE(data.subarray(0, 4))),
        Number(bytesToNumberLE(data.subarray(4, 8))) 
    ];
    const join = (ns: number[]): TRet<Uint8Array> => concatBytes(
        numberToBytesLE(ns[1], 4),
        numberToBytesLE(ns[0], 4)
    );

    return {
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const paddedData = pad1(msg, cipher.blockSize);

            let prev = split(iv).reverse();
            for(let i = 0; i < paddedData.length; i += cipher.blockSize) prev = split(cipher.proceedBlock(
                xorBytes(paddedData.subarray(i, i + cipher.blockSize), join(prev)),
                magmaKeySequences.MAC
            ));

            return join(prev);
        }
    }
}

/**
 * **EN:** Message Authentication Code with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM) mode
 * 
 * **RU:** Режим выработки имитовставки с преобразованием ключа (ACPKM)
 */
export const omac_acpkm = (cipher: Cipher): MACMode => {
    const sectionSize = cipher.blockSize * 2;

    return {
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            let encrypter = cipher.encrypt.bind(cipher);
            let tail_offset = 0;
            if(msg.length % cipher.blockSize == 0) tail_offset = msg.length - cipher.blockSize;
            else tail_offset = msg.length - (msg.length % cipher.blockSize);

            let prev: Uint8Array = new Uint8Array(cipher.blockSize).fill(0);
            let sections = msg.length;
            if (msg.length % sectionSize != 0) sections += 1;

            let keymats = acpkm_master(cipher, (32 + cipher.blockSize) * sections);

            let k1 = new Uint8Array(sectionSize);
            for(let i = 0; i < tail_offset; i += cipher.blockSize) {
                if (i % sectionSize == 0) {
                    let keymat = keymats.slice(0, 32 + cipher.blockSize);
                        keymats = keymats.slice(32 + cipher.blockSize);
                    let key = keymat.slice(0, 32);
                    k1 = keymat.slice(32);
                    // @ts-ignore
                    let cipher2 = new cipher.constructor(key);
                    encrypter = cipher2.encrypt.bind(cipher2);
                }
                prev = encrypter(xorBytes(msg.slice(i, i + cipher.blockSize), prev));
            }

            const tail = msg.slice(tail_offset);
            if(tail.length == cipher.blockSize) {
                let key = keymats.slice(0, 32);
                k1 = keymats.slice(32);
                // @ts-ignore
                let cipher2 = new cipher.constructor(key);
                encrypter = cipher2.encrypt.bind(cipher2);
            }
            let k2 = numberToVarBytesBE(bytesToNumberBE(k1) << 1n);
            if((k1.slice()[0] & 0x80) != 0)
                k2 = xorBytes(k2, numberToVarBytesBE(cipher.blockSize == 16 ? Rb128 : Rb64));
            return encrypter(xorBytes(
                xorBytes(pad3(tail, cipher.blockSize), prev),
                (tail.length == cipher.blockSize) ? k1 : k2
            ));
        }
    }
}
