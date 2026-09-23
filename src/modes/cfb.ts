import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { xorBytes } from "../utils.js";
import { MESH_MAX_DATA, meshing } from "./_keytransform.js";

/**
 * **EN:** Cipher Feedback (CFB) mode
 * 
 * **RU:** Режим гаммирования с обратной связью по шифртексту
 */
export const cfb = (cipher: Cipher, iv: TArg<Uint8Array>, mesh?: boolean): BlockMode => {
    const bs = cipher.blockSize;
    if (iv.length === 0 || iv.length % bs !== 0) throw new Error("Invalid IV size");
    if (mesh && iv.length !== bs) throw new Error("Key meshing requires a single-block IV");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let activeCipher = cipher;
            let encrypter = activeCipher.encrypt.bind(activeCipher);

            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(plaintext.length);
            for (let n = 0; n < Math.ceil(plaintext.length / bs); n++) {
                const i = n * bs;
                if (mesh && i >= MESH_MAX_DATA && i % MESH_MAX_DATA === 0) {
                    const meshed = meshing(activeCipher, r[r.length - 1]);
                    activeCipher = meshed.cipher;
                    encrypter = activeCipher.encrypt.bind(activeCipher);
                    r[r.length - 1] = meshed.iv;
                }
                const chunkLen = Math.min(bs, plaintext.length - i);
                const ct = xorBytes(plaintext.subarray(i, i + chunkLen), encrypter(r[0]));
                out.set(ct, i);
                r.shift();
                r.push(ct);
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            let activeCipher = cipher;
            let encrypter = activeCipher.encrypt.bind(activeCipher);
            
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(ciphertext.length);
            for (let n = 0; n < Math.ceil(ciphertext.length / bs); n++) {
                const i = n * bs;
                if (mesh && i >= MESH_MAX_DATA && i % MESH_MAX_DATA === 0) {
                    const meshed = meshing(activeCipher, r[r.length - 1]);
                    activeCipher = meshed.cipher;
                    encrypter = activeCipher.encrypt.bind(activeCipher);
                    r[r.length - 1] = meshed.iv;
                }
                const chunkLen = Math.min(bs, ciphertext.length - i);
                const blk = ciphertext.subarray(i, i + chunkLen);
                out.set(xorBytes(blk, encrypter(r[0])), i);
                r.shift();
                r.push(blk);
            }

            return out;
        }
    });
}