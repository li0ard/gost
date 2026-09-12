import { bytesToNumberLE, numberToBytesBE, numberToBytesLE, concatBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import type { Cipher, StreamMode } from "../types.js";
import { xorBytes } from "../utils.js";
import type { Magma } from "../magma/index.js";
import { acpkm } from "./_keytransform.js";

const C1 = 0x01010104n, C2 = 0x01010101n;

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
    const ctrMax = 1n << (8n * BigInt(halfBlockSize));
    const maxSize = ctrMax * BigInt(cipher.blockSize);

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            let encrypter = cipher.encrypt.bind(cipher);
            if (BigInt(msg.length) > maxSize) throw new Error("Too big data");
            let acpkmSectionSize = 0;
            if(isAcpkm) acpkmSectionSize = _isAcpkmOmac
                ? (cipher.blockSize == 16 ? 6 : 10)
                : 2;

            const keystreamBlocks: Uint8Array[] = [];
            for (let ctr = 0; ctr < Math.ceil(msg.length / cipher.blockSize); ctr++) {
                if(isAcpkm && ctr != 0 && (ctr % acpkmSectionSize) == 0) {
                    // @ts-ignore
                    const cipher2 = new cipher.constructor(acpkm(encrypter, cipher.blockSize));
                    encrypter = cipher2.encrypt.bind(cipher2);
                }
                keystreamBlocks.push(encrypter(concatBytes(iv, numberToBytesBE(ctr, halfBlockSize))));
            }

            return xorBytes(concatBytes(...keystreamBlocks), msg);
        }
    });
}

/**
 * **EN:** Counter (CTR) mode (GOST 28147-89)
 * 
 * **RU:** Режим гаммирования (ГОСТ 28147-89)
 */
export const cnt = (cipher: Magma, iv: TArg<Uint8Array>): StreamMode => {
    if(iv.length !== cipher.blockSize) throw new Error("Invalid IV size");

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            const encryptedIv = cipher.encrypt(iv);
            let n1 = bytesToNumberLE(encryptedIv.subarray(0,4)),
                n2 = bytesToNumberLE(encryptedIv.subarray(4));

            const output = new Uint8Array(msg.length);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                n1 = (n1 + C2) & 0xFFFFFFFFn;
                n2 = (n2 + C1) % 0xFFFFFFFFn;
                const ct = xorBytes(msg.subarray(i, i + cipher.blockSize), cipher.encrypt(concatBytes(
                    numberToBytesLE(n1, 4),
                    numberToBytesLE(n2, 4)
                )));
                output.set(ct, i);
            }

            return output;
        }
    });
}