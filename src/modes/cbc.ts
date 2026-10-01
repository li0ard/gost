import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { BlockMode, Cipher } from "../types.js";
import { abytesAligned, xorBytes } from "../utils.js";
import { MESH_MAX_DATA, meshing } from "./_keytransform.js";

/**
 * **EN:** Cipher Block Chaining (CBC) mode
 * 
 * **RU:** Режим простой замены с зацеплением
 */
export const cbc = (cipher: Cipher, iv: TArg<Uint8Array>, mesh?: boolean): BlockMode => {
    const bs = cipher.blockSize;
    abytesAligned(iv, bs, "iv");
    if (mesh && iv.length !== bs) throw new Error("Key meshing requires a single-block IV");

    return Object.freeze({
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(plaintext, bs, "plaintext");
            let activeCipher = cipher;
            let encrypter = activeCipher.encrypt.bind(activeCipher);

            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(plaintext.length);
            for (let i = 0; i < plaintext.length; i += bs) {
                if (mesh && i >= MESH_MAX_DATA && i % MESH_MAX_DATA === 0) {
                    activeCipher = meshing(activeCipher, iv).cipher;
                    encrypter = activeCipher.encrypt.bind(activeCipher);
                }
                const block = encrypter(xorBytes(r[0], plaintext.subarray(i, i + bs)));
                out.set(block, i);
                r.shift();
                r.push(block);
            }

            return out;
        },
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytesAligned(ciphertext, bs, "ciphertext");
            let activeCipher = cipher;
            let decrypter = activeCipher.decrypt.bind(activeCipher);
            const r: Uint8Array[] = [];
            for (let i = 0; i < iv.length; i += bs) r.push(iv.subarray(i, i + bs));

            const out = new Uint8Array(ciphertext.length);
            for (let i = 0; i < ciphertext.length; i += bs) {
                if (mesh && i >= MESH_MAX_DATA && i % MESH_MAX_DATA === 0) {
                    activeCipher = meshing(activeCipher, iv).cipher;
                    decrypter = activeCipher.decrypt.bind(activeCipher);
                }
                const blk = ciphertext.subarray(i, i + bs);
                out.set(xorBytes(r[0], decrypter(blk)), i);
                r.shift();
                r.push(blk);
            }

            return out;
        }
    });
}