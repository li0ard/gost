import { numberToBytesBE, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import type { Cipher, CipherCtor, StreamMode } from "../types.js";
import { xorBytes } from "../utils.js";
import { acpkm } from "./_keytransform.js";
import { createView } from "@noble/hashes/utils.js";

const C1 = 0x01010104, C2 = 0x01010101;

/**
 * **EN:** Counter (CTR) mode
 * 
 * **RU:** Режим гаммирования
 */
export const ctr = (
    cipher: Cipher,
    iv: TArg<Uint8Array>,
    isAcpkm?: boolean,
    _isAcpkmOmac?: boolean
): StreamMode => {
    const halfBlockSize = cipher.blockSize / 2;
    if (iv.length !== halfBlockSize) throw new Error("Invalid IV size");
    const ctrMax = 1n << (8n * BigInt(halfBlockSize)),
        maxSize = ctrMax * BigInt(cipher.blockSize),
        acpkmSectionSize = _isAcpkmOmac
        ? (cipher.blockSize == 16 ? 6 : 10)
        : 2,
    CipherCtor = cipher.constructor as CipherCtor;

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            let encrypter = cipher.encrypt.bind(cipher);
            if (BigInt(msg.length) > maxSize) throw new Error("Too big data");

            const out = new Uint8Array(msg.length);
            for (let ctr = 0; ctr < Math.ceil(msg.length / cipher.blockSize); ctr++) {
                if (isAcpkm && ctr !== 0 && ctr % acpkmSectionSize === 0) {
                    const cipher2 = new CipherCtor(acpkm(encrypter, cipher.blockSize));
                    encrypter = cipher2.encrypt.bind(cipher2);
                }

                const gamma = encrypter(concatBytes(iv, numberToBytesBE(ctr, halfBlockSize)));
                const offset = ctr * cipher.blockSize;
                out.set(xorBytes(msg.subarray(offset, offset + cipher.blockSize), gamma), offset);
            }

            return out;
        }
    });
}

/**
 * **EN:** Counter (CTR) mode (GOST 28147-89)
 * 
 * **RU:** Режим гаммирования (ГОСТ 28147-89)
 */
export const cnt = (cipher: Cipher, iv: TArg<Uint8Array>): StreamMode => {
    if(iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    const incrementCounter = (ctr: TArg<Uint8Array>) => {
        const view = createView(ctr);
        view.setUint32(0, (view.getUint32(0, true) + C2) >>> 0, true);
        let s2 = view.getUint32(4, true) + C1;
        if (s2 >= 0xFFFFFFFF) s2 -= 0xFFFFFFFF;
        view.setUint32(4, s2 >>> 0, true);
    }

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const ctr = cipher.encrypt(iv),
                output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                incrementCounter(ctr);
                const ct = xorBytes(msg.subarray(i, i + cipher.blockSize), cipher.encrypt(ctr));
                output.set(ct, i);
            }

            return output;
        }
    });
}