import { type TArg, type TRet, bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";

export const gf128Multiply = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    let x = bytesToNumberBE(a), y = bytesToNumberBE(b), z = 0n;
    const max_bit = 1n << 127n;

    while (y > 0n) {
        if((y & 1n) == 1n) z ^= x;
        if((x & max_bit) > 0n) x = ((x ^ max_bit) << 1n) ^ 0x87n;
        else x <<= 1n;
        y >>= 1n;
    }

    return numberToBytesBE(z, 16);
}