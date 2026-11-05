import { abytes, anumber, type TArg, type TRet } from "@noble/hashes/utils.js";

export const _2_32 = 0x100000000;

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length),
        result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const xorBytesInPlace = (dst: TArg<Uint8Array>, src: TArg<Uint8Array>, off = 0) => {
    if (off + dst.length > src.length) throw new Error("src is too short");
    for(let i = 0; i < dst.length; i++) dst[i] ^= src[off + i];
}

const atitle = (title: string): string => title ? `"${title}" ` : '';

export const abytesAligned = (
    value: TArg<Uint8Array>,
    blockSize: number,
    title: string = ""
): TRet<Uint8Array> => {
    abytes(value);
    anumber(blockSize);
    if (value.length !== 0 && value.length % blockSize === 0) return value as TRet<Uint8Array>;
    
    const ofLen = ` of length aligned to ${blockSize}`,
        got = `length=${value.length}`,
        message = atitle(title) + 'expected Uint8Array' + ofLen + ', got ' + got;
    throw new RangeError(message);
}

export const reverseBytes = (
    b: TArg<Uint8Array>,
    from?: number,
    to?: number
): TRet<Uint8Array> => b.slice(from, to).reverse();

export const splitBlocks = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array[]> => {
    const blocks = [];
    for (let i = 0; i < data.length; i += blockSize) blocks.push(data.subarray(i, i + blockSize));
    return blocks as TRet<Uint8Array[]>;
}