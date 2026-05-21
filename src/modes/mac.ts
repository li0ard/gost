import { type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, MACMode } from "../types.js";
import { pad1, pad3, xorBytes } from "../utils.js";
import { bytesToNumberBE, numberToVarBytesBE } from "@noble/curves/utils.js";
import { magmaKeySequences, Magma } from "../magma/index.js";
import { acpkm_master } from "./_keytransform.js";

const Rb64 = 0b11011;
const Rb128 = 0b10000111;

/**
 * **EN:** Message Authentication Code (MAC) mode
 * 
 * **RU:** Режим выработки имитовставки
 */
export const mac = (cipher: Cipher): MACMode => {
    const encrypter = cipher.encrypt.bind(cipher);
    const macShift = (data: TArg<Uint8Array>, xorLsb: number = 0): TRet<Uint8Array> => numberToVarBytesBE(
        (bytesToNumberBE(data) * BigInt(2)) ^ BigInt(xorLsb)
    ).slice(-cipher.blockSize);

    const macKs = (): TRet<Uint8Array>[] => {
        const Rb = cipher.blockSize === 16 ? Rb128 : Rb64;
        const l = encrypter(new Uint8Array(cipher.blockSize));

        let k1;
        if ((l[0] & 0x80) !== 0) k1 = macShift(l, Rb);
        else k1 = macShift(l);

        let k2;
        if ((k1[0] & 0x80) !== 0) k2 = macShift(k1, Rb);
        else k2 = macShift(k1);

        return [k1, k2];
    }

    return {
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const [k1, k2] = macKs();
            let tailOffset: number;
            if (msg.length % cipher.blockSize === 0) tailOffset = msg.length - cipher.blockSize;
            else tailOffset = msg.length - (msg.length % cipher.blockSize);
            
            let prev: Uint8Array = new Uint8Array(cipher.blockSize);
            for (let i = 0; i < tailOffset; i += cipher.blockSize)
                prev = encrypter(xorBytes(msg.subarray(i, i + cipher.blockSize), prev));
            const tail = msg.subarray(tailOffset);
            const xorWithPrev = xorBytes(pad3(tail, cipher.blockSize), prev);
            return encrypter(xorBytes(xorWithPrev, (tail.length === cipher.blockSize ? k1 : k2)));
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
        (data[0] | data[1] << 8 | data[2] << 16 | data[3] << 24) >>> 0,
        (data[4] | data[5] << 8 | data[6] << 16 | data[7] << 24) >>> 0
    ];
    const join = (ns: number[]): TRet<Uint8Array> => new Uint8Array([
        (ns[1] >> 0) & 0xFF, (ns[1] >> 8) & 0xFF, (ns[1] >> 16) & 0xFF, (ns[1] >> 24) & 0xFF,
        (ns[0] >> 0) & 0xFF, (ns[0] >> 8) & 0xFF, (ns[0] >> 16) & 0xFF, (ns[0] >> 24) & 0xFF
    ]);

    return {
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const paddedData = pad1(msg, cipher.blockSize);

            let prev = split(iv).reverse();
            for(let i = 0; i < paddedData.length; i += cipher.blockSize) prev = split(Magma.reverseChunks(cipher.proceedBlock(
                Magma.reverseChunks(xorBytes(paddedData.subarray(i, i + cipher.blockSize), join(prev))),
                magmaKeySequences.MAC
            )));

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
