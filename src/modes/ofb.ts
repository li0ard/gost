import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Cipher, StreamMode } from "../types.js";
import { xorBytes, getPadLength } from "../utils.js";
/**
 * **EN:** Output Feedback (OFB) mode
 * 
 * **RU:** Режим гаммирования с обратной связью по выходу
 */
export const ofb = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    if (iv.length == 0 || iv.length % cipher.blockSize !== 0)
        throw new Error("Invalid IV size");
    const encrypter = cipher.encrypt.bind(cipher);

    return {
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize) r.push(iv.slice(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < (msg.length + getPadLength(msg.length, cipher.blockSize)); i += cipher.blockSize) {
                r = r.slice(1).concat(encrypter(r[0]));
                result.push(xorBytes(r[r.length - 1], msg.subarray(i, i + cipher.blockSize)));
            }

            return concatBytes(...result);
        }
    }
}