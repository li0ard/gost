import { bytesToNumberLE, numberToBytesLE, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import type { Cipher, CipherCtor, MACMode } from "../types.js";
import { pad1, pad3, xorBytes } from "../utils.js";
import { magmaKeySequences, Magma } from "../magma/index.js";
import { acpkm_master } from "./_keytransform.js";

const Rb64 = 0b11011, Rb128 = 0b10000111, ACPKM_MASTER_KEYSIZE = 32;

const shift1 = (src: TArg<Uint8Array>, dst: TArg<Uint8Array>): number => {
    let b = 0;
    for(let i = src.length - 1; i >= 0; i--) {
        const bb = src[i] >> 7;
        dst[i] = src[i] << 1 | b;
        b = bb;
    }

    return b;
}

const gfDouble = (k: TArg<Uint8Array>, Rb: number): TRet<Uint8Array> => {
    const out = new Uint8Array(k.length);
    if (shift1(k, out)) out[out.length - 1] ^= Rb;
    return out;
}

/**
 * **EN:** Message Authentication Code (MAC) mode
 * 
 * **RU:** Режим выработки имитовставки
 */
export const mac = (cipher: Cipher): MACMode => {
    const bs = cipher.blockSize,
        Rb = bs === 16 ? Rb128 : Rb64,
        L = cipher.encrypt(new Uint8Array(bs)),
        K1 = gfDouble(L, Rb), K2 = gfDouble(K1, Rb);

    return Object.freeze({
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const n = Math.ceil(msg.length / bs) || 1;
            const lastBlockIsFull = msg.length > 0 && msg.length % bs === 0;
            const tailOffset = (n - 1) * bs;

            let prev = new Uint8Array(bs);
            for (let i = 0; i < tailOffset; i += bs)
                prev = cipher.encrypt(xorBytes(prev, msg.subarray(i, i + bs)));

            let lastBlock;
            if (lastBlockIsFull)
                lastBlock = xorBytes(msg.subarray(tailOffset, tailOffset + bs), K1);
            else {
                const tail = msg.subarray(tailOffset);
                const padded = new Uint8Array(bs);
                padded.set(tail);
                padded[tail.length] = 0x80;
                lastBlock = xorBytes(padded, K2);
            }

            return cipher.encrypt(xorBytes(prev, lastBlock));
        }
    });
}

/**
 * **EN:** Message Authentication Code (MAC) mode (GOST 28147-89)
 * 
 * **RU:** Режим выработки имитовставки (ГОСТ 28147-89)
 */
export const mac_legacy = (
    cipher: Magma,
    iv: TArg<Uint8Array> = new Uint8Array(cipher.blockSize)
): MACMode => Object.freeze({
    compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
        const paddedData = pad1(msg, cipher.blockSize);

        let prev0 = bytesToNumberLE(iv.subarray(4, 8)),
            prev1 = bytesToNumberLE(iv.subarray(0, 4));
        const feedback = new Uint8Array(cipher.blockSize);
        for (let i = 0; i < paddedData.length; i += cipher.blockSize) {
            feedback.set(numberToBytesLE(prev1, 4), 0);
            feedback.set(numberToBytesLE(prev0, 4), 4);

            const out = cipher.proceedBlock(
                xorBytes(paddedData.subarray(i, i + cipher.blockSize), feedback),
                magmaKeySequences.MAC
            );

            prev0 = bytesToNumberLE(out.subarray(0, 4));
            prev1 = bytesToNumberLE(out.subarray(4, 8));
        }

        return concatBytes(numberToBytesLE(prev1, 4), numberToBytesLE(prev0, 4));
    }
});

/**
 * **EN:** Message Authentication Code with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM) mode
 * 
 * **RU:** Режим выработки имитовставки с преобразованием ключа (ACPKM)
 */
export const omac_acpkm = (cipher: Cipher): MACMode => {
    const bs = cipher.blockSize,
        sectionSize = bs * 2,
        Rb = bs === 16 ? Rb128 : Rb64,
        keymatSize = ACPKM_MASTER_KEYSIZE + bs,
        CipherCtor = cipher.constructor as CipherCtor;

    return Object.freeze({
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const tailOffset = msg.length % bs === 0
                ? msg.length - bs
                : msg.length - (msg.length % bs);

            let sections = Math.floor(msg.length / sectionSize);
            if (msg.length % sectionSize !== 0) sections += 1;
            if (sections === 0) sections = 1;

            let keymats: Uint8Array = acpkm_master(cipher, keymatSize * sections);
            let encrypter = cipher.encrypt.bind(cipher);
            let k1: Uint8Array = new Uint8Array(bs);
            let rotated = false;

            const rotateKey = () => {
                const key = keymats.subarray(0, ACPKM_MASTER_KEYSIZE);
                k1 = keymats.subarray(ACPKM_MASTER_KEYSIZE, keymatSize);
                keymats = keymats.subarray(keymatSize);

                const cipher2 = new CipherCtor(key);
                encrypter = cipher2.encrypt.bind(cipher2);
                rotated = true;
            }

            let prev = new Uint8Array(bs);
            for (let i = 0; i < tailOffset; i += bs) {
                if (i % sectionSize === 0) rotateKey();
                prev = encrypter(xorBytes(msg.subarray(i, i + bs), prev));
            }

            const tail = msg.subarray(tailOffset);
            if (tail.length === bs) rotateKey();
            if (!rotated) rotateKey();

            const k2 = gfDouble(k1, Rb);

            return encrypter(xorBytes(
                xorBytes(pad3(tail, bs), prev),
                tail.length === bs ? k1 : k2
            ));
        }
    });
}