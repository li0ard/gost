import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { getPadLength, xorBytes } from "../utils.js";

/**
 * **EN:** Cipher Feedback (CFB) mode
 * 
 * **RU:** Режим гаммирования с обратной связью по шифртексту
 */
export const cfb = (cipher: Cipher, iv: TArg<Uint8Array>): BlockMode => {
    if (iv.length == 0 || iv.length % cipher.blockSize !== 0)
        throw new Error("Invalid IV size");
    const encrypter = cipher.encrypt.bind(cipher);

    return {
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.slice(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < (plaintext.length + getPadLength(plaintext.length, cipher.blockSize)); i += cipher.blockSize) {
                result.push(xorBytes(encrypter(r[0]), plaintext.subarray(i, i + cipher.blockSize)));
                r = r.slice(1).concat(result[result.length - 1]);
            }

            return concatBytes(...result);
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.slice(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < (ciphertext.length + getPadLength(ciphertext.length, cipher.blockSize)); i += cipher.blockSize) {
                const blk = ciphertext.slice(i, i + cipher.blockSize);
                result.push(xorBytes(encrypter(r[0]), blk));
                r = r.slice(1).concat(blk);
            }

            return concatBytes(...result);
        }
    }
}