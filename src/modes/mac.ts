import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, CipherCtor, MACMode } from "../types.js";
import { filled, xorBytesInPlace } from "../utils.js";
import { magmaKeySequences, type Magma } from "../magma/index.js";
import { ctr } from "./ctr.js";

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

const acpkm_master = (cipher: Cipher, length: number): TRet<Uint8Array> => ctr(
    cipher,
    filled(cipher.blockSize / 2, 0xff),
    true, true
).crypt(new Uint8Array(length));

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
            abytes(msg, undefined, "msg");
            const n = Math.ceil(msg.length / bs) || 1,
                tailOffset = (n - 1) * bs;

            let prev = new Uint8Array(bs);
            for (let i = 0; i < tailOffset; i += bs) {
                xorBytesInPlace(prev, msg, i);
                prev = cipher.encrypt(prev);
            }

            if (msg.length > 0 && msg.length % bs === 0) {
                xorBytesInPlace(prev, msg, tailOffset);
                xorBytesInPlace(prev, K1);
            } else {
                const tailLength = msg.length - tailOffset;
                xorBytesInPlace(prev.subarray(0, tailLength), msg, tailOffset);
                prev[tailLength] ^= 0x80;
                xorBytesInPlace(prev, K2);
            }

            return cipher.encrypt(prev);
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
): MACMode => {
    abytes(iv, undefined, "iv");
    const half = cipher.blockSize / 2;

    return Object.freeze({
        compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            const feedback = new Uint8Array(cipher.blockSize),
                block = new Uint8Array(cipher.blockSize);
            feedback.set(iv.subarray(0, cipher.blockSize));

            const step = () => {
                const out = cipher.proceedBlock(block, magmaKeySequences.MAC);
                feedback.set(out.subarray(half));
                feedback.set(out.subarray(0, half), half);
            }

            const tailOffset = msg.length - (msg.length % cipher.blockSize);
            for (let i = 0; i < tailOffset; i += cipher.blockSize) {
                block.set(feedback);
                xorBytesInPlace(block, msg, i);
                step();
            }

            if (msg.length % cipher.blockSize !== 0 || msg.length === 0) {
                block.set(feedback);
                xorBytesInPlace(block.subarray(0, msg.length - tailOffset), msg, tailOffset);
                step();
            }

            return feedback;
        }
    });
}

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
            abytes(msg, undefined, "msg");
            const tailOffset = msg.length % bs === 0
                ? msg.length - bs
                : msg.length - (msg.length % bs);

            const sections = Math.ceil(msg.length / sectionSize) || 1;

            let keymats: Uint8Array = acpkm_master(cipher, keymatSize * sections),
                encrypter = cipher.encrypt.bind(cipher),
                k1: Uint8Array = new Uint8Array(bs),
                rotated = false;

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
                xorBytesInPlace(prev, msg, i);
                prev = encrypter(prev);
            }

            const tail = msg.subarray(tailOffset);
            if (tail.length === bs) rotateKey();
            if (!rotated) rotateKey();

            if (tail.length === bs) {
                xorBytesInPlace(prev, tail);
                xorBytesInPlace(prev, k1);
            } else {
                xorBytesInPlace(prev.subarray(0, tail.length), tail);
                prev[tail.length] ^= 0x80;
                xorBytesInPlace(prev, gfDouble(k1, Rb));
            }

            return encrypter(prev);
        }
    });
}