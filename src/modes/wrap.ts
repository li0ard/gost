import { concatBytes, type TArg, type TRet, equalBytes } from "@noble/curves/utils.js";
import type { Cipher, WrapMode, WrapModeMagma } from "../types.js";
import { mac as _mac, mac_legacy } from "./mac.js";
import { ctr } from "./ctr.js";
import { ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET } from "../magma/const.js";
import { Magma } from "../magma/index.js";
import { ecb } from "./ecb.js";
import { cp_kek_diversify } from "./_keytransform.js";

/** 
 * **EN:** KExp15/KImp15 key wrapping
 * 
 * **RU:** Режим обёртки ключей шифрования KExp15/KImp15
 */
export const kexp15 = (cipherEnc: Cipher, cipherMac: Cipher, iv: TArg<Uint8Array>): WrapMode => {
    if(iv.length != (cipherEnc.blockSize / 2) || iv.length != (cipherMac.blockSize / 2))
        throw new Error("Invalid IV size");

    return Object.freeze({
        wrap: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const mac = _mac(cipherMac).compute(concatBytes(iv, msg));
            return ctr(cipherEnc, iv).crypt(concatBytes(msg, mac));
        },
        unwrap: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const keymac = ctr(cipherEnc, iv).crypt(msg);
            const key = keymac.slice(0, -cipherEnc.blockSize)
            const mac = _mac(cipherMac).compute(concatBytes(iv, key));
            if(!equalBytes(keymac.subarray(-cipherEnc.blockSize), mac))
                throw new Error("Invalid key MAC");

            return key;
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
    sbox: TArg<Uint8Array> = ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET
): WrapModeMagma => Object.freeze({
    wrap: (ukm: TArg<Uint8Array>, cek: TArg<Uint8Array>): TRet<Uint8Array> => {
        const cipher = new Magma(isCryptoPro ? cp_kek_diversify(kek, ukm, sbox) : kek, sbox, true);

        const cek_mac = mac_legacy(cipher, ukm).compute(cek).subarray(0,4);
        const cek_enc = ecb(cipher).encrypt(cek);

        return concatBytes(ukm, cek_enc, cek_mac);
    },
    unwrap: (wrapped: TArg<Uint8Array>) => {
        if(wrapped.length !== 44 && wrapped.length !== 76)
            throw new Error("Invalid data length");

        const [ukm, cek_enc, cek_mac] = [wrapped.subarray(0, 8), wrapped.subarray(8, wrapped.length-4), wrapped.subarray(-4)];
        const cipher = new Magma(isCryptoPro ? cp_kek_diversify(kek, ukm, sbox) : kek, sbox, true);
        const cek = ecb(cipher).decrypt(cek_enc);

        const mac_computed = mac_legacy(cipher, ukm).compute(cek).subarray(0,4);
        if(!equalBytes(cek_mac, mac_computed))
            throw new Error("Invalid MAC");

        return cek;
    }
});