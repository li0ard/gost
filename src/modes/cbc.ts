import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { xorBytes } from "../utils.js";

/**
 * **EN:** Cipher Block Chaining (CBC) mode
 * 
 * **RU:** Режим простой замены с зацеплением
 */
export const cbc = (cipher: Cipher, iv: TArg<Uint8Array>): BlockMode => {
    if (iv.length == 0 || iv.length % cipher.blockSize !== 0)
        throw new Error("Invalid IV size");
    
    const encrypter = cipher.encrypt.bind(cipher);
    const decrypter = cipher.decrypt.bind(cipher);

    return {
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (plaintext.length == 0 || plaintext.length % cipher.blockSize !== 0)
                throw new Error("Data not aligned");
            
            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < plaintext.length; i += cipher.blockSize) {
                result.push(encrypter(xorBytes(r[0], plaintext.subarray(i, i + cipher.blockSize))));
                r = r.slice(1).concat(result[result.length-1]);
            }

            return concatBytes(...result);
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            if (ciphertext.length == 0 || ciphertext.length % cipher.blockSize !== 0)
                throw new Error("Data not aligned");

            let r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += cipher.blockSize)
                r.push(iv.subarray(i, i + cipher.blockSize));

            const result: Uint8Array[] = [];
            for(let i = 0; i < ciphertext.length; i += cipher.blockSize) {
                const blk = ciphertext.slice(i, i + cipher.blockSize);
                result.push(xorBytes(r[0], decrypter(blk)));
                r = r.slice(1).concat(blk);
            }

            return concatBytes(...result);
        }
    }
}