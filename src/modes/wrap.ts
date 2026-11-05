import { abytes, concatBytes, type TArg, type TRet, equalBytes, abool } from "@noble/curves/utils.js";
import type { Cipher, WrapMode, WrapModeMagma } from "../types.js";
import { mac as _mac, mac_legacy } from "./mac.js";
import { ctr } from "./ctr.js";
import { MagmaLegacy } from "../magma/index.js";
import { ecb } from "./ecb.js";
import { cp_kek_diversify } from "./_keytransform.js";

/** 
 * **EN:** KExp15/KImp15 key wrapping
 * 
 * **RU:** Режим обёртки ключей шифрования KExp15/KImp15
 */
export const kexp15 = (cipherEnc: Cipher, cipherMac: Cipher, iv: TArg<Uint8Array>): WrapMode => {
    abytes(iv, cipherEnc.blockSize / 2, "iv");
    abytes(iv, cipherMac.blockSize / 2, "iv");

    return Object.freeze({
        wrap: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            const mac = _mac(cipherMac).compute(concatBytes(iv, msg));
            return ctr(cipherEnc, iv).crypt(concatBytes(msg, mac));
        },
        unwrap: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            const keymac = ctr(cipherEnc, iv).crypt(msg),
                key = keymac.subarray(0, -cipherEnc.blockSize),
                mac = _mac(cipherMac).compute(concatBytes(iv, key));
            if(!equalBytes(keymac.subarray(-cipherEnc.blockSize), mac))
                throw new Error("Invalid key MAC");

            return key as TRet<Uint8Array>;
        }
    });
}

/** 
 * **EN:** GOST 28147-89 key wrapping
 * 
 * **RU:** Режим обёртки ключей шифрования согласно ГОСТ 28147-89
 */
export const kwp = (
    kek: TArg<Uint8Array>,
    isCryptoPro: boolean = false,
    sbox?: TArg<Uint8Array>
): WrapModeMagma => {
    abytes(kek, undefined, "kek");
    abool(isCryptoPro, "isCryptoPro");
    if(sbox) abytes(sbox, 64, "sbox");
    return Object.freeze({
        wrap: (ukm: TArg<Uint8Array>, cek: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(ukm, undefined, "ukm");
            abytes(cek, undefined, "cek");
            const cipher = new MagmaLegacy(isCryptoPro ? cp_kek_diversify(kek, ukm, sbox) : kek, sbox),
                mac = mac_legacy(cipher, ukm).compute(cek).subarray(0,4);

            return concatBytes(ukm, ecb(cipher).encrypt(cek), mac);
        },
        unwrap: (wrapped: TArg<Uint8Array>) => {
            abytes(wrapped, undefined, "wrapped");
            if(wrapped.length !== 44 && wrapped.length !== 76)
                throw new Error("Invalid data length");

            const ukm = wrapped.subarray(0,8),
                cipher = new MagmaLegacy(isCryptoPro ? cp_kek_diversify(kek, ukm, sbox) : kek, sbox),
                dec = ecb(cipher).decrypt(wrapped.subarray(8, -4));

            const mac_computed = mac_legacy(cipher, ukm).compute(dec).subarray(0,4);
            if(!equalBytes(wrapped.subarray(-4), mac_computed))
                throw new Error("Invalid MAC");

            return dec;
        }
    });
}