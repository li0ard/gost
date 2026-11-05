import { abytes, copyBytes, type TArg, type TRet, equalBytes, anumber } from "@noble/curves/utils.js";
import type { AEADMode, Cipher } from "../types.js";
import { _2_32, xorBytesInPlace } from "../utils.js";
import { gf64Multiply, gf128Multiply } from "../gf/index.js"; 
import { createView } from "@noble/hashes/utils.js";

/**
 * **EN:** Multilinear Galois (MGM) mode (AEAD)
 * 
 * **RU:** Режим шифрования с имитозащитой и ассоциированными данными (AEAD)
 */
export const mgm = (cipher: Cipher, nonce: TArg<Uint8Array>, tagSize = cipher.blockSize): AEADMode => {
    const bs = cipher.blockSize;
    if (bs !== 8 && bs !== 16)
        throw new Error("Only 64/128-bit blocksizes allowed");
    abytes(nonce, bs, "nonce");
    anumber(tagSize, "tagSize");
    if (tagSize < 4 || tagSize > bs)
        throw new Error("Invalid tagSize");
    if ((nonce[0] & 0x80) !== 0)
        throw new Error("Nonce must not have its high bit set");

    const halfbs = cipher.blockSize / 2,
        mul = cipher.blockSize === 8 ? gf64Multiply : gf128Multiply,
        maxSize = (1n << BigInt(bs * 4)) - 1n;

    const incr = (view: DataView, off: number = 0) => {
        const low = off + halfbs - 4,
            value = (view.getUint32(low) + 1) >>> 0;
        view.setUint32(low, value);
        if (value === 0 && halfbs > 4)
            view.setUint32(low - 4, (view.getUint32(low - 4) + 1) >>> 0);
    }

    const putBits = (view: DataView, off: number, bytes: number) => {
        const bits = bytes * 8;
        if (bits >= 2 ** (8 * halfbs)) 
            throw new Error("Data length is too big");
        view.setUint32(off + halfbs - 4, bits >>> 0);
        if (halfbs > 4)
            view.setUint32(off, Math.floor(bits / _2_32));
    }

    const validateSizes = (plaintext: TArg<Uint8Array>, aad: TArg<Uint8Array>) => {
        if (plaintext.length === 0 && aad.length === 0)
            throw new Error("At least one of plaintext or additional data required");
        if (BigInt(plaintext.length) + BigInt(aad.length) > maxSize)
            throw new Error("plaintext + additional data are too big");
    }

    const crypt = (icn: TArg<Uint8Array>, data: TArg<Uint8Array>) => {
        icn[0] &= 0x7F;
        const enc = cipher.encrypt(icn), view = createView(enc);
        for (let offset = 0; offset < data.length; offset += bs) {
            xorBytesInPlace(data.subarray(offset, offset + bs), cipher.encrypt(enc));
            incr(view, halfbs);
        }
    }

    const auth = (icn: TArg<Uint8Array>, text: TArg<Uint8Array>, aad: TArg<Uint8Array>): TRet<Uint8Array> => {
        icn[0] |= 0x80;
        const enc = cipher.encrypt(icn), encView = createView(enc),
            sum = new Uint8Array(bs);
        const updateSum = (block: TArg<Uint8Array>) => {
            xorBytesInPlace(sum, mul(cipher.encrypt(enc), block));
            incr(encView);
        }
        const absorb = (data: TArg<Uint8Array>) => {
            for (let offset = 0; offset < data.length; offset += bs) {
                const chunk: Uint8Array = data.subarray(offset, offset + bs);
                if (chunk.length === bs) updateSum(chunk);
                else {
                    const padded = new Uint8Array(bs);
                    padded.set(chunk);
                    updateSum(padded);
                }
            }
        }
        absorb(aad);
        absorb(text);

        const lengths = new Uint8Array(bs), lengthsView = createView(lengths);
        putBits(lengthsView, 0, aad.length);
        putBits(lengthsView, halfbs, text.length);
        xorBytesInPlace(sum, mul(cipher.encrypt(enc), lengths));

        return cipher.encrypt(sum).subarray(0, tagSize) as TRet<Uint8Array>;
    }

    return Object.freeze({
        seal: (plaintext: TArg<Uint8Array>, aad: TArg<Uint8Array> = new Uint8Array()): TRet<Uint8Array> => {
            abytes(plaintext, undefined, "plaintext");
            abytes(aad, undefined, "aad");
            validateSizes(plaintext, aad);
            const icn = copyBytes(nonce),
                out = new Uint8Array(plaintext.length + tagSize),
                ciphertext = out.subarray(0, plaintext.length);
            ciphertext.set(plaintext);
            crypt(icn, ciphertext);
            out.set(auth(icn, ciphertext, aad), plaintext.length);

            return out;
        },
        open: (ciphertext: TArg<Uint8Array>, aad: TArg<Uint8Array> = new Uint8Array()): TRet<Uint8Array> => {
            abytes(ciphertext, undefined, "ciphertext");
            abytes(aad, undefined, "aad");
            validateSizes(ciphertext, aad);
            if (ciphertext.length < tagSize)
                throw new Error("Ciphertext is shorter than tag size");
            const icn = copyBytes(nonce),
                ct = ciphertext.subarray(0, -tagSize),
                tag = auth(icn, ct, aad);
            if (!equalBytes(ciphertext.subarray(-tagSize), tag))
                throw new Error("Invalid authentication tag");

            const plaintext = copyBytes(ct);
            crypt(icn, plaintext);

            return plaintext;
        }
    });
}