import { type TArg, type TRet, bytesToNumberLE, concatBytes, copyBytes, numberToBytesLE } from "@noble/curves/utils.js";
import { Magma } from "../magma/index.js";
import { ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET } from "../magma/const.js";
import { cfb } from "./cfb.js";
import type { Cipher, CipherOrHashFunctionWrapper } from "../types.js";
import { ctr } from "./ctr.js";

export const cp_kek_diversify = (
    kek: TArg<Uint8Array>,
    ukm: TArg<Uint8Array>,
    sbox: TArg<Uint8Array> = ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET
): TRet<Uint8Array> => {
    let out = copyBytes(kek);
    for (let i = 0; i < 8; i++) {
        let s1 = 0, s2 = 0;
        for (let j = 0; j < 8; j++) {
            const k = Number(bytesToNumberLE(out.subarray(j*4, j*4+4)));
            if ((ukm[i] >> j) & 1) s1 += k;
            else s2 += k;
        }

        const iv = concatBytes(numberToBytesLE(s1 >>> 0, 4), numberToBytesLE(s2 >>> 0, 4));
        out = cfb(new Magma(out, sbox, true), iv).encrypt(out);
    }

    return out as TRet<Uint8Array>;
}

const ACPKM_D = new Uint8Array([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
]);

export const acpkm = (encrypter: CipherOrHashFunctionWrapper, bs: number): TRet<Uint8Array> => {
    const result: Uint8Array[] = [];
    for (let i = 0; i < 32; i += bs) {
        const block = ACPKM_D.subarray(i, i + bs);
        result.push(encrypter(block));
    }

    return concatBytes(...result);
}

export const acpkm_master = (cipher: Cipher, length: number): TRet<Uint8Array> => ctr(
    cipher,
    new Uint8Array(cipher.blockSize / 2).fill(0xFF),
    true, true
).crypt(new Uint8Array(length));