import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { abytesAligned, xorBytes } from "../utils.js";

/**
 * **EN:** Cipher Feedback (CFB) mode
 * 
 * **RU:** Режим гаммирования с обратной связью по шифртексту
 */
export const cfb = (cipher: Cipher, iv: TArg<Uint8Array>): BlockMode => {
    const bs = cipher.blockSize;
    abytesAligned(iv, bs, "iv");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(plaintext, undefined, "plaintext");
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(plaintext.length);
            for (let n = 0; n < Math.ceil(plaintext.length / bs); n++) {
                const i = n * bs;
                const ct = xorBytes(plaintext.subarray(i, i + bs), cipher.encrypt(r[0]));
                out.set(ct, i);
                r.shift();
                r.push(ct);
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ciphertext, undefined, "ciphertext");
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(ciphertext.length);
            for (let n = 0; n < Math.ceil(ciphertext.length / bs); n++) {
                const i = n * bs;
                const ct = ciphertext.subarray(i, i + bs);
                out.set(xorBytes(ct, cipher.encrypt(r[0])), i);
                r.shift();
                r.push(ct);
            }

            return out;
        }
    });
}