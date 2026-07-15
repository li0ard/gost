import { bytesToNumberBE, concatBytes, numberToBytesBE, randomBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import type { GostCurveParameters } from "./const.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { weierstrass } from "@noble/curves/abstract/weierstrass.js";

/**
 * Generate public key from private.
 * @param parameters Curve parameters
 * @param prv Private key
 * @returns {TRet<Uint8Array>} Uncompressed public key in ANSI X9.62 format
 */
export const getPublicKey = (
    parameters: GostCurveParameters,
    prv: TArg<Uint8Array>
): TRet<Uint8Array> => weierstrass(parameters).BASE.multiply(bytesToNumberBE(prv)).toBytes(false);

/**
 * Generate signature of provided digest
 * @param parameters Curve parameters
 * @param prv Private key
 * @param digest Digest to sign
 * @param rand Optional. Predefined random data for `k` generation
 * @returns {TRet<Uint8Array>} Concatenated `r` and `s` (in BE order)
 */
export const sign = (
    parameters: GostCurveParameters,
    prv: TArg<Uint8Array>,
    digest: TArg<Uint8Array>,
    rand?: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const size = parameters.length;
    const curve = weierstrass(parameters);
    const Fn = curve.Fn;
    let e = mod(bytesToNumberBE(digest), Fn.ORDER);
    if(e === 0n) e = 1n;

    const prvNum = mod(bytesToNumberBE(prv), Fn.ORDER);
    while (true) {
        rand ||= randomBytes(size)
        const k = mod(bytesToNumberBE(rand), parameters.n);
        if(k === 0n) continue;
        try {
            const r = mod(curve.BASE.multiply(k).x, Fn.ORDER);
            if(r === 0n) continue;
            
            const s = Fn.add(Fn.mul(r, prvNum), Fn.mul(k, e));
            if (s === 0n) continue;

            return concatBytes(
                numberToBytesBE(r, parameters.length),
                numberToBytesBE(s, parameters.length)
            );
        } catch(e) {
            if(e instanceof Error && e.message === "invalid scalar: out of range")
                continue;
            throw e;
        }
    }
}

/**
 * Verify signature of provided digest
 * @param parameters Curve parameters
 * @param pub Public key
 * @param digest Digest to verify
 * @param signature Signature (Concatenated `r` and `s`) (in BE order)
 */
export const verify = (
    parameters: GostCurveParameters,
    pub: TArg<Uint8Array>,
    digest: TArg<Uint8Array>,
    signature: TArg<Uint8Array>
): boolean => {
    const size = parameters.length;
    const curve = weierstrass(parameters);
    const Fn = curve.Fn;

    if(signature.length != size * 2) throw new Error("Invalid signature");

    const r = bytesToNumberBE(signature.subarray(0, size)),
        s = bytesToNumberBE(signature.subarray(size));
    if(r <= 0 || r >= parameters.n || s <= 0 || s >= parameters.n) return false;

    let e = mod(bytesToNumberBE(digest), Fn.ORDER);
    if(e === 0n) e = 1n;

    const v = Fn.inv(e);
    const z1 = Fn.mul(s, v), z2 = Fn.mul(r, v);
    let P, Q;
    try {
        P = curve.BASE.multiply(z1);
        Q = curve.fromBytes(pub).multiply(z2).negate();
    } catch { return false; }

    return mod(P.add(Q).x, Fn.ORDER) === r;
}

/** Swap `r` and `s` in signature */
export const swapPoint = (curve: GostCurveParameters, point: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    point.subarray(curve.length),
    point.subarray(0, curve.length),
);

export * from "./const.js";
export * from "./vko.js";
export * from "./conversion.js";