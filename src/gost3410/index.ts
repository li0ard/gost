/**
 * Implementation of GOST R 34.10-2001 ([RFC 5832](https://datatracker.ietf.org/doc/html/rfc5832.html)) and GOST R 34.10-2012 ([RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091.html))
 * signature scheme and key exchange (VKO)
 * 
 * Difference between GOST R 34.10-2001 and GOST R 34.10-2012 is key/digest/signature lengths
 * and curves OID's
 * 
 * **Signature not verified? Try to:**
 * - Reverse signature
 * - Swap signature halves (and reverse it too)
 * - Reverse digest
 * - Reverse/swap public key
 * 
 * Unfortunately, GOST doesn't unify serialization
 * 
 * API is close to `@noble/curves`
 * @module
 */
import { bytesToNumberBE, concatBytes, numberToBytesBE, type TArg, type TRet, numberToBytesLE, type CHash, randomBytes, abytes } from "@noble/curves/utils.js";
import type { GostCurveParameters } from "./const.js";
import { getMinHashLength, mapHashToField, mod, type IField } from "@noble/curves/abstract/modular.js";
import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { streebog256hmac, streebog512hmac } from "../hmac.js";
import { createKeygen, type AffinePoint } from "@noble/curves/abstract/curve.js";
import type { Signer } from "../types.js";

const getWLengths = <T>(Fp: TArg<IField<T>>, Fn: TArg<IField<bigint>>) => ({
    secretKey: Fn.BYTES,
    publicKey: 1 + Fp.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp.BYTES,
    publicKeyHasPrefix: true,
    signature: 2 * Fn.BYTES,
});

/** Swap `x` and `y` in point bytes */
const swapPoint = (point: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    point.subarray(point.length / 2),
    point.subarray(0, point.length / 2),
);

/** Creates GOST R 34.10-2012 (2001) signing interface */
export const gost3410 = (parameters: GostCurveParameters): Signer => {
    const Point = weierstrass(parameters);
    const { Fp, Fn, BASE } = Point;

    const lengths = Object.assign(getWLengths(Fp, Fn), {
        seed: Math.max(getMinHashLength(Fn.ORDER), 16),
    });

    /**
     * Computes public key for a secret key. Checks for validity of the secret key.
     * @param isCompressed - whether to return compact (default), or full key
     * @returns Public key, full when `isCompressed=false`; short when `isCompressed=true`
     */
    const getPublicKey = (
        secretKey: TArg<Uint8Array>, 
        isCompressed: boolean = true
    ): TRet<Uint8Array> => BASE.multiply(Fn.fromBytes(secretKey)).toBytes(isCompressed);

    /**
     * Signs a message hash with a secret key.
     * 
     * ```
     * sign(d, m) where
     *   k = streebog_hmac_drbg(d, m)
     *   (x, y) = G × k
     *   r = x mod n
     *   s = (rd + km) mod n
     * ```
     */
    const sign = (secretKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, rand?: TArg<Uint8Array>) => {
        const e = mod(bytesToNumberBE(digest), Fn.ORDER) || 1n;
        const d = Fn.fromBytes(secretKey);
        if(!Fn.isValidNot0(d)) throw new Error("Invalid private key");
        const hmac = parameters.length == 32 ? streebog256hmac : streebog512hmac;

        const k = rand
            ? mod(bytesToNumberBE(rand), Fn.ORDER)
            : mod(
                bytesToNumberBE(hmac(secretKey, digest)),
                Fn.ORDER - 1n
            ) + 1n;

        const r = mod(BASE.multiply(k).x, Fn.ORDER),
            s = Fn.add(Fn.mul(r, d), Fn.mul(k, e));

        return concatBytes(
            numberToBytesBE(r, parameters.length),
            numberToBytesBE(s, parameters.length)
        );
    }

    /**
     * Verifies a signature against message hash and public key.
     * 
     * ```
     * verify(P, m, r, s) where
     *   v = m^-1 mod n
     *   z1 = sv mod n
     *   z2 = -rv mod n
     *   R = (z1 × G + z2 × P).x mod n
     *   R == r
     * ```
     */
    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>
    ) => {
        if(signature.length != lengths.signature) throw new Error("Invalid signature");

        const r = bytesToNumberBE(signature.subarray(0, parameters.length)),
        s = bytesToNumberBE(signature.subarray(parameters.length));
        if(!Fn.isValidNot0(r) || !Fn.isValidNot0(s)) return false;

        const e = mod(bytesToNumberBE(digest), Fn.ORDER) || 1n;

        const v = Fn.inv(e);
        const z1 = Fn.mul(s, v), z2 = Fn.mul(Fn.neg(r), v);
        let P, Q;
        try {
            P = BASE.multiply(z1);
            Q = Point.fromBytes(publicKey).multiply(z2);
        } catch { return false; }

        return mod(P.add(Q).x, Fn.ORDER) === r;
    }

    /**
     * Key agreement function (ECDH)
     * 
     * Computes hashed shared point from secret key A and public key B.
     * @param hash Hash function to use (GOST R 34.11-94, Streebog-256, Streebog-512)
     * @param ukm User keying material (aka salt, VKO-factor)
     */
    const getSharedSecret = (
        hash: CHash,
        secretKeyA: TArg<Uint8Array>,
        publicKeyB: TArg<Uint8Array>,
        ukm: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const key = Point.fromBytes(publicKeyB)
        .multiply(Fn.fromBytes(secretKeyA))
        .multiply(Fn.mulN(parameters.h, bytesToNumberBE(ukm)));

        return hash(concatBytes(
            numberToBytesLE(key.x, parameters.length),
            numberToBytesLE(key.y, parameters.length)
        ));
    }

    const randomSecretKey = (seed?: TArg<Uint8Array>): TRet<Uint8Array> => mapHashToField(
        abytes(seed ?? randomBytes(lengths.seed), lengths.seed, 'seed'), 
        Fn.ORDER
    );

    const keygen = createKeygen(randomSecretKey, getPublicKey);
    Object.freeze(lengths);

    const computeST = (): bigint[] => {
        if(!parameters.e || !parameters.d) throw new Error("No Twisted Edwards parameters");
        if(parameters.st && parameters.st.length != 0) return parameters.st;

        return [
            Fp.div(Fp.sub(parameters.e, parameters.d), 4n), 
            Fp.div(Fp.add(parameters.e, parameters.d), 6n)
        ];
    }

    const uv2xy = (point: AffinePoint<bigint>): AffinePoint<bigint> => {
        const [s, t] = computeST();
        const s1v = Fp.mul(s, Fp.add(1n, point.y)),
            _1v = Fp.sub(1n, point.y);

        return {
            x: Fp.add(t, Fp.div(s1v, _1v)),
            y: Fp.div(s1v, Fp.mul(point.x, _1v))
        }
    }

    const xy2uv = (point: AffinePoint<bigint>): AffinePoint<bigint> => {
        const [s, t] = computeST();
        const xt = Fp.sub(point.x, t);

        return {
            x: Fp.div(xt, point.y),
            y: Fp.div(Fp.sub(xt, s), Fp.add(xt, s))
        }
    }

    const utils = Object.freeze({ uv2xy, xy2uv, swapPoint });

    return Object.freeze({
        getPublicKey,
        sign,
        verify,
        getSharedSecret,
        Point,
        keygen,
        lengths,
        utils
    });
}

export * from "./const.js";