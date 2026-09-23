import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { Cipher, StreamMode } from "../types.js";
import { xorBytes } from "../utils.js";

/**
 * **EN:** Output Feedback (OFB) mode
 * 
 * **RU:** Режим гаммирования с обратной связью по выходу
 */
export const ofb = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    const bs = cipher.blockSize;
    if (iv.length === 0 || iv.length % bs !== 0) throw new Error("Invalid IV size");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(msg.length);
            for (let n = 0; n < Math.ceil(msg.length / bs); n++) {
                const i = n * bs;
                const gamma = cipher.encrypt(r[0]);
                r.shift();
                r.push(gamma);

                const chunkLen = Math.min(bs, msg.length - i);
                out.set(xorBytes(msg.subarray(i, i + chunkLen), gamma), i);
            }

            return out;
        }
    });
}