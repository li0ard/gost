import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { AEADMode, Cipher } from "../types.js";
import { bytesToNumberBE, equalBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { pad1, xorBytes } from "../utils.js";
import { gf64Multiply, gf128Multiply } from "../gf/index.js"; 
/**
 * **EN:** Multilinear Galois (MGM) mode (AEAD)
 * 
 * **RU:** Режим шифрования с имитозащитой и ассоциированными данными (AEAD)
 */
export const mgm = (cipher: Cipher, nonce: TArg<Uint8Array>, tagSize = cipher.blockSize): AEADMode => {
    const halfbs = cipher.blockSize / 2;
    const _incr = (data: TArg<Uint8Array>): TRet<Uint8Array> =>
        numberToBytesBE(bytesToNumberBE(data) + 1n, halfbs);
    const incr_r = (data: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
        data.subarray(0, halfbs),
        _incr(data.subarray(halfbs))
    );
    const incr_l = (data: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
        _incr(data.subarray(0, halfbs)),
        data.subarray(halfbs)
    );

    if(tagSize < 4 || tagSize > cipher.blockSize)
        throw new Error("Invalid tagSize");

    const encrypter = cipher.encrypt.bind(cipher);
    const maxSize = (1n << BigInt(cipher.blockSize * 4)) - 1n;

    const validateSizes = (plaintext: TArg<Uint8Array>, additional: TArg<Uint8Array>) => {
        if(plaintext.length == 0 && additional.length == 0)
            throw new Error("At least one of plaintext or additional_data required");
        if((plaintext.length + additional.length) > maxSize)
            throw new Error("plaintext+additional_data are too big");
    }

    const mul = (cipher.blockSize == 8 ? gf64Multiply : gf128Multiply);

    const crypt = (icn: TArg<Uint8Array>, data: TArg<Uint8Array>) => {
        icn[0] &= 0x7F;
        let enc = encrypter(icn);
        const res: Uint8Array[] = [];
        while (data.length > 0) {
            res.push(xorBytes(encrypter(enc), data));
            enc = incr_r(enc);
            data = data.slice(cipher.blockSize);
        }
        return concatBytes(...res);
    }

    const auth = (icn: TArg<Uint8Array>, text: TArg<Uint8Array>, ad: TArg<Uint8Array>) => {
        icn[0] |= 0x80;
        let enc = encrypter(icn);
        let _sum = new Uint8Array(cipher.blockSize);
        const ad_len = ad.length;
        const text_len = text.length;
        while (ad.length > 0) {
            _sum = xorBytes(_sum, mul(
                encrypter(enc),
                pad1(ad.subarray(0, cipher.blockSize), cipher.blockSize)
            ));
            enc = incr_l(enc);
            ad = ad.slice(cipher.blockSize);
        }

        while (text.length > 0) {
            _sum = xorBytes(_sum, mul(
                encrypter(enc),
                pad1(text.subarray(0, cipher.blockSize), cipher.blockSize)
            ));
            enc = incr_l(enc);
            text = text.slice(cipher.blockSize);
        }

        _sum = xorBytes(_sum, mul(encrypter(enc), concatBytes(
            numberToBytesBE(ad_len * 8, halfbs),
            numberToBytesBE(text_len * 8, halfbs),
        )));

        return encrypter(_sum).subarray(0, tagSize);
    }

    return {
        seal: (plaintext: TArg<Uint8Array>, aad: TArg<Uint8Array> = new Uint8Array()): TRet<Uint8Array> => {
            validateSizes(plaintext, aad);

            const icn = nonce.slice();
            const ciphertext = crypt(icn, plaintext);
            const tag = auth(icn, ciphertext, aad);
            return concatBytes(ciphertext, tag);
        },

        open: (ciphertext: TArg<Uint8Array>, aad: TArg<Uint8Array> = new Uint8Array()): TRet<Uint8Array> => {
            validateSizes(ciphertext, aad);

            const icn = nonce.slice();
            const ct = ciphertext.slice(0, (ciphertext.length - tagSize));
            const tag_expected = ciphertext.subarray((ciphertext.length - tagSize));
            const tag = auth(icn, ct, aad);
            if(!equalBytes(tag_expected, tag))
                throw new Error("Invalid authentication tag");

            return crypt(icn, ct);
        }
    }
}