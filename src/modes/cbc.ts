import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { abytesAligned, xorBytes } from "../utils.js";

/**
 * **EN:** Cipher Block Chaining (CBC) mode
 * 
 * **RU:** Режим простой замены с зацеплением
 */
export const cbc = (cipher: Cipher, iv: TArg<Uint8Array>): BlockMode => {
    const bs = cipher.blockSize;
    abytesAligned(iv, bs, "iv");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(plaintext, bs, "plaintext");
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(plaintext.length);
            for (let i = 0; i < plaintext.length; i += bs) {
                const block = cipher.encrypt(xorBytes(r[0], plaintext.subarray(i, i + bs)));
                out.set(block, i);
                r.shift();
                r.push(block);
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(ciphertext, bs, "ciphertext");
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(ciphertext.length);
            for (let i = 0; i < ciphertext.length; i += bs) {
                const blk = ciphertext.subarray(i, i + bs);
                out.set(xorBytes(r[0], cipher.decrypt(blk)), i);
                r.shift();
                r.push(blk);
            }

            return out;
        }
    });
}