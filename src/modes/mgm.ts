import { concatBytes, copyBytes, type TArg, type TRet, bytesToNumberBE, equalBytes, numberToBytesBE } from "@noble/curves/utils.js";
import type { AEADMode, Cipher } from "../types.js";
import { pad1, xorBytes, xorBytesInPlace } from "../utils.js";
import { gf64Multiply, gf128Multiply } from "../gf/index.js"; 

/**
 * **EN:** Multilinear Galois (MGM) mode (AEAD)
 * 
 * **RU:** Режим шифрования с имитозащитой и ассоциированными данными (AEAD)
 */
export const mgm = (cipher: Cipher, nonce: TArg<Uint8Array>, tagSize = cipher.blockSize): AEADMode => {
    const bs = cipher.blockSize;
    if (bs !== 8 && bs !== 16)
        throw new Error("Only 64/128-bit blocksizes allowed");
    if (tagSize < 4 || tagSize > bs)
        throw new Error("Invalid tagSize");
    if (nonce.length !== bs)
        throw new Error("Nonce length must be equal to cipher's blocksize");
    if ((nonce[0] & 0x80) !== 0)
        throw new Error("Nonce must not have its high bit set");

    const halfbs = cipher.blockSize / 2,
        mul = cipher.blockSize === 8 ? gf64Multiply : gf128Multiply,
        maxSize = (1n << BigInt(bs * 4)) - 1n;
    
    const _incr = (data: TArg<Uint8Array>): TRet<Uint8Array> =>
        numberToBytesBE(bytesToNumberBE(data) + 1n, halfbs),
        incr_r = (data: TArg<Uint8Array>) => data.set(_incr(data.subarray(halfbs)), halfbs),
        incr_l = (data: TArg<Uint8Array>) => data.set(_incr(data.subarray(0, halfbs)));

    const validateSizes = (plaintext: TArg<Uint8Array>, aad: TArg<Uint8Array>) => {
        if (plaintext.length === 0 && aad.length === 0)
            throw new Error("At least one of plaintext or additional data required");
        if (BigInt(plaintext.length) + BigInt(aad.length) > maxSize)
            throw new Error("plaintext + additional data are too big");
    }

    const crypt = (icn: TArg<Uint8Array>, data: TArg<Uint8Array>): TRet<Uint8Array> => {
        icn[0] &= 0x7F;
        const enc = cipher.encrypt(icn), out = new Uint8Array(data.length);
        for (let offset = 0; offset < data.length; offset += bs) {
            out.set(xorBytes(
                cipher.encrypt(enc),
                data.subarray(offset, offset + bs)
            ), offset);
            incr_r(enc);
        }

        return out;
    }

    const auth = (icn: TArg<Uint8Array>, text: TArg<Uint8Array>, aad: TArg<Uint8Array>): TRet<Uint8Array> => {
        icn[0] |= 0x80;
        const enc = cipher.encrypt(icn), sum = new Uint8Array(bs);
        const updateSum = (data: TArg<Uint8Array>) => {
            xorBytesInPlace(sum, mul(cipher.encrypt(enc), data));
            incr_l(enc);
        }
        for (let offset = 0; offset < aad.length; offset += bs)
            updateSum(pad1(aad.subarray(offset, offset + bs), bs));
        for (let offset = 0; offset < text.length; offset += bs)
            updateSum(pad1(text.subarray(offset, offset + bs), bs));

        xorBytesInPlace(sum, mul(cipher.encrypt(enc), concatBytes(
            numberToBytesBE(BigInt(aad.length) * 8n, halfbs),
            numberToBytesBE(BigInt(text.length) * 8n, halfbs),
        )));

        return cipher.encrypt(sum).subarray(0, tagSize) as TRet<Uint8Array>;
    }

    return Object.freeze({
        seal: (plaintext: TArg<Uint8Array>, aad: TArg<Uint8Array> = new Uint8Array()): TRet<Uint8Array> => {
            validateSizes(plaintext, aad);
            const icn = copyBytes(nonce),
                ciphertext = crypt(icn, plaintext);
            return concatBytes(ciphertext, auth(icn, ciphertext, aad));
        },

        open: (ciphertext: TArg<Uint8Array>, aad: TArg<Uint8Array> = new Uint8Array()): TRet<Uint8Array> => {
            validateSizes(ciphertext, aad);
            if (ciphertext.length < tagSize)
                throw new Error("Ciphertext is shorter than tag size");
            const icn = copyBytes(nonce),
                ct = ciphertext.subarray(0, -tagSize),
                tag = auth(icn, ct, aad);
            if (!equalBytes(ciphertext.subarray(-tagSize), tag))
                throw new Error("Invalid authentication tag");

            return crypt(icn, ct);
        }
    });
}