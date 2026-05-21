import type { TArg, TRet } from "@noble/hashes/utils.js";

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const getPadLength = (dataLength: number, blockSize: number): number => {
    if(dataLength < blockSize) return blockSize - dataLength;
    if(dataLength % blockSize == 0) return 0;
    return blockSize - dataLength % blockSize;
}

export const pad1 = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> => {
    const padded = new Uint8Array(data.length + getPadLength(data.length, blockSize));
    padded.set(data);
    return padded;
}

export const pad2 = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> => {
    const padded = new Uint8Array(data.length + 1 + getPadLength(data.length + 1, blockSize));
    padded.set(data, 0);
    padded[data.length] = 0x80;
    return padded;
}

export const unpad2 = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> => {
    const lastBlock = data.subarray(data.length - blockSize);
    let padIndex = -1;

    for (let i = lastBlock.length - 1; i >= 0; i--) {
        if (lastBlock[i] == 0x80) {
            padIndex = i;
            break;
        }
    }

    if (padIndex === -1) throw new Error("Padding marker (0x80) not found");
    for (let i = padIndex + 1; i < lastBlock.length; i++) {
        if (lastBlock[i] !== 0) throw new Error("Invalid padding: non-zero bytes after 0x80");
    }

    return data.slice(0, data.length - (blockSize - padIndex));
}

export const pad3 = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> => {
    if(getPadLength(data.length, blockSize) == 0) return data as TRet<Uint8Array>;
    return pad2(data, blockSize);
}