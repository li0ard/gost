import { bytesToNumberBE, numberToBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";

const gf2m_multiply = (
    degree: bigint,
    poly: bigint,
    a: TArg<Uint8Array>,
    b: TArg<Uint8Array>
): TRet<Uint8Array> => {
    let x = bytesToNumberBE(a), y = bytesToNumberBE(b), z = 0n;
    const max_bit = 1n << (degree - 1n);

    while (y > 0n) {
        if((y & 1n) == 1n) z ^= x;
        if((x & max_bit) > 0n) x = ((x ^ max_bit) << 1n) ^ poly;
        else x <<= 1n;
        y >>= 1n;
    }

    return numberToBytesBE(z, Number(degree / 8n));
}

export const gf64Multiply = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => gf2m_multiply(
    64n,
    0x1Bn,
    a,b
);

export const gf128Multiply = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => gf2m_multiply(
    128n,
    0x87n,
    a,b
);

export { gf256Multiply } from "./gf256.js";