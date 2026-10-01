import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, StreamMode } from "../types.js";
import { abytesAligned, xorBytes } from "../utils.js";

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
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(msg.length);
            for (let n = 0; n < Math.ceil(msg.length / bs); n++) {
                const i = n * bs;
                const gamma = cipher.encrypt(r[0]);
                r.shift();
                r.push(gamma);
                out.set(xorBytes(msg.subarray(i, i + bs), gamma), i);
            }

            return out;
        }
    });
}