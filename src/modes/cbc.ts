import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { abytesAligned, splitBlocks, xorBytesInPlace } from "../utils.js";

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
            const r = splitBlocks(iv, bs), out = new Uint8Array(plaintext.length);
            let h = 0;
            for (let i = 0; i < plaintext.length; i += bs) {
                const block = out.subarray(i, i + bs);
                block.set(plaintext.subarray(i, i + bs));
                xorBytesInPlace(block, r[h]);
                block.set(cipher.encrypt(block));
                r[h] = block;
                h = (h + 1) % r.length;
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(ciphertext, bs, "ciphertext");
            const r = splitBlocks(iv, bs), out = new Uint8Array(ciphertext.length);
            let h = 0;
            for (let i = 0; i < ciphertext.length; i += bs) {
                const blk = ciphertext.subarray(i, i + bs),
                    block = out.subarray(i, i + bs);
                block.set(cipher.decrypt(blk));
                xorBytesInPlace(block, r[h]);
                r[h] = blk as TRet<Uint8Array>;
                h = (h + 1) % r.length;
            }

            return out;
        }
    });
}