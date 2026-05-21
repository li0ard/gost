import { type TArg, type TRet, bytesToNumberLE, concatBytes, copyBytes, numberToBytesLE } from "@noble/curves/utils.js";
import { Magma } from "../magma/index.js";
import { ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET } from "../magma/const.js";
import { cfb } from "./cfb.js";
import type { Cipher } from "../types.js";
import { ctr } from "./ctr.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { ecb } from "./ecb.js";

export const cp_kek_diversify = (
    kek: TArg<Uint8Array>,
    ukm: TArg<Uint8Array>,
    sbox: TArg<Uint8Array>[] = ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET
): TRet<Uint8Array> => {
    let out = copyBytes(kek);
    for (let i = 0; i < 8; i++) {
        let s1 = 0, s2 = 0;
        for (let j = 0; j < 8; j++) {
            const k = Number(bytesToNumberLE(out.subarray(j*4, j*4+4))); //((out[j * 4]) | (out[j * 4 + 1] << 8) | (out[j * 4 + 2] << 16) | (out[j * 4 + 3] << 24)) >>> 0;
            if ((ukm[i] >> j) & 1) s1 += k;
            else s2 += k;
        }

        const iv = concatBytes(numberToBytesLE(s1 >>> 0, 4), numberToBytesLE(s2 >>> 0, 4));
        const cipher = new Magma(out, sbox, true);
        out = cfb(cipher, iv).encrypt(out);
    }

    return out as TRet<Uint8Array>;
}

export const acpkm = (encrypter: (msg: TArg<Uint8Array>) => TRet<Uint8Array>, bs: number): TRet<Uint8Array> => {
    const result: Uint8Array[] = [];
    for (let d = 0x80; d < (0x80 + bs * (32 / bs)); d += bs) {
        const block = new Uint8Array(bs);
        for (let i = 0; i < bs; i++) block[i] = d + i;
        result.push(encrypter(block));
    }

    return concatBytes(...result);
}

export const acpkm_master = (cipher: Cipher, length: number): TRet<Uint8Array> => ctr(
    cipher,
    new Uint8Array(cipher.blockSize / 2).fill(0xFF),
    true, true
).crypt(new Uint8Array(length));