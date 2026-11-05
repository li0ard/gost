import { abool, abytes, createView , type TArg, type TRet, copyBytes } from "@noble/hashes/utils.js";
import type { Cipher, CipherCtor, StreamMode } from "../types.js";
import { xorBytesInPlace, _2_32 } from "../utils.js";
import { acpkm } from "./_keytransform.js";

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
    abytes(iv, halfBlockSize, "iv");
    if(isAcpkm) abool(isAcpkm);
    if(_isAcpkmOmac) abool(_isAcpkmOmac);
    const ctrMax = 1n << (8n * BigInt(halfBlockSize)),
        maxSize = ctrMax * BigInt(cipher.blockSize),
        acpkmSectionSize = _isAcpkmOmac
            ? (cipher.blockSize === 16 ? 6 : 10)
            : 2,
        CipherCtor = cipher.constructor as CipherCtor;

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            if (BigInt(msg.length) > maxSize) throw new Error("Too big data");

            let encrypter = cipher.encrypt.bind(cipher);
            const out = copyBytes(msg),
                block = new Uint8Array(cipher.blockSize),
                blockView = createView(block);
            block.set(iv);

            for (let i = 0; i < Math.ceil(msg.length / cipher.blockSize); i++) {
                if (isAcpkm && i !== 0 && i % acpkmSectionSize === 0) {
                    const cipher2 = new CipherCtor(acpkm(encrypter, cipher.blockSize));
                    encrypter = cipher2.encrypt.bind(cipher2);
                }

                blockView.setUint32(cipher.blockSize - 4, i >>> 0);
                if (halfBlockSize > 4)
                    blockView.setUint32(cipher.blockSize - 8, Math.floor(i / _2_32));

                const offset = i * cipher.blockSize;
                xorBytesInPlace(out.subarray(offset, offset + cipher.blockSize), encrypter(block));
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
    abytes(iv, cipher.blockSize, "iv");

    const incrementCounter = (view: DataView) => {
        view.setUint32(0, (view.getUint32(0, true) + C2) >>> 0, true);
        let s2 = view.getUint32(4, true) + C1;
        if (s2 >= 0xFFFFFFFF) s2 -= 0xFFFFFFFF;
        view.setUint32(4, s2 >>> 0, true);
    }

    return Object.freeze({
        crypt: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
            abytes(msg, undefined, "msg");
            const ctr = cipher.encrypt(iv), ctrView = createView(ctr),
                output = copyBytes(msg);
            for (let i = 0; i < msg.length; i += cipher.blockSize) {
                incrementCounter(ctrView);
                xorBytesInPlace(output.subarray(i, i + cipher.blockSize), cipher.encrypt(ctr));
            }

            return output;
        }
    });
}