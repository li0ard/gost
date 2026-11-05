import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, StreamMode } from "../types.js";
import { abytesAligned, splitBlocks, xorBytesInPlace } from "../utils.js";

/**
 * **EN:** Output Feedback (OFB) mode
 * 
 * **RU:** Режим гаммирования с обратной связью по выходу
 */
export const ofb = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    const bs = cipher.blockSize;
    abytesAligned(iv, bs, "iv");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            const r = splitBlocks(iv, bs), out = new Uint8Array(msg.length);
            let h = 0;
            for (let i = 0; i < msg.length; i += bs) {
                const gamma = cipher.encrypt(r[h]),
                    block = out.subarray(i, i + bs);
                block.set(msg.subarray(i, i + bs));
                xorBytesInPlace(block, gamma);
                r[h] = gamma;
                h = (h + 1) % r.length;
            }

            return out;
        }
    });
}