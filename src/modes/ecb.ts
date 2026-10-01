import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher, CipherOrHashFunctionWrapper } from "../types.js";
import { abytesAligned } from "../utils.js";

/**
 * **EN:** Electronic Codebook (ECB) mode
 * 
 * **RU:** Режим простой замены
 */
export const ecb = (cipher: Cipher): BlockMode => {
    const encrypter = cipher.encrypt.bind(cipher);
    const decrypter = cipher.decrypt.bind(cipher);

    const core = (crypter: CipherOrHashFunctionWrapper, data: TArg<Uint8Array>): TRet<Uint8Array> => {
        const output = new Uint8Array(data.length);
        for(let i = 0; i < data.length; i += cipher.blockSize)
            output.set(crypter(data.subarray(i, i + cipher.blockSize)), i);

        return output;
    }

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> =>
            core(encrypter, abytesAligned(plaintext, cipher.blockSize, "plaintext")),
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> =>
            core(decrypter, abytesAligned(ciphertext, cipher.blockSize, "ciphertext")),
    });
}