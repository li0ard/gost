import type { IField } from "@noble/curves/abstract/modular.js";
import { concatBytes, bytesToNumberBE, numberToBytesBE, randomBytes, type TArg } from "@noble/curves/utils.js";
import { streebog256hmac, streebog512hmac } from "../hmac.js";

const zero = new Uint8Array([0x00]), one = new Uint8Array([0x01]);

/** 
 * Crates minimal HMAC-DRBG from RFC 6979 for GOST curves
 * 
 * Supports Hedged signatures, technique described in RFC 6979 section 3.6,
 * a.k.a. adding randomness in deterministic signature
 * 
 * Uses HMAC over Streebog-256 for 256 bit curves and HMAC overStreebog-512 for 512 curves
 */
export const createStreebogHmacDrbg = (Fn: TArg<IField<bigint>>) => {
    if(Fn.BYTES != 32 && Fn.BYTES != 64)
        throw new Error("Unsupported field size: Fiest must be 32 or 64 bytes long")
    if(Math.ceil(Fn.BITS / 8) != Fn.BYTES)
        throw new Error("Unsupported field: Field isn't byte-aligned");
    const hmac = Fn.BYTES == 32 ? streebog256hmac : streebog512hmac;

    const bits2int = (bytes: TArg<Uint8Array>): bigint => {
        const blen = bytes.length * 8;
        let x = bytesToNumberBE(bytes);
        if (blen > Fn.BITS) x >>= BigInt(blen - Fn.BITS);

        return x;
    }

    return (privateKey: bigint, digest: TArg<Uint8Array>, extraEntropy?: boolean): bigint => {
        const seedArgs: Uint8Array[] = [
            numberToBytesBE(privateKey, Fn.BYTES),
            numberToBytesBE(Fn.create(bits2int(digest)), Fn.BYTES)
        ];
        if(extraEntropy) seedArgs.push(randomBytes(Fn.BYTES));
        const seed = concatBytes(...seedArgs);
    
        const V = new Uint8Array(Fn.BYTES).fill(0x01),
            K = hmac(new Uint8Array(Fn.BYTES), concatBytes(V, zero, seed));
        V.set(hmac(K, V));
        K.set(hmac(K, concatBytes(V, one, seed)));
        V.set(hmac(K, V));

        while (true) {
            let T = new Uint8Array();
            while (T.length < Fn.BYTES) {
                V.set(hmac(K, V));
                T = concatBytes(T, V);
            }

            const k = bits2int(T);
            if (Fn.isValidNot0(k)) return k;
            K.set(hmac(K, concatBytes(V, zero)));
            V.set(hmac(K, V));
        }
    }
}