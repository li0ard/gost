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
 * Unfortunately, GOST doesn't unify serialization, this realization serialize as in standard (Big-Endian)
 * 
 * API is close to `@noble/curves`
 * @module
 */
import { bytesToNumberBE, concatBytes, type TArg, type TRet, randomBytes, abytes } from "@noble/curves/utils.js";
import {
    type GostCurveParameters,
    ID_GOSTR3410_2001_PARAM_SET_CC, ID_GOSTR3410_2001_TEST_PARAM_SET,
    ID_GOSTR3410_2012_256_PARAM_SET_A, ID_GOSTR3410_2012_256_PARAM_SET_B,
    ID_GOSTR3410_2012_256_PARAM_SET_C, ID_GOSTR3410_2012_256_PARAM_SET_D,
    ID_GOSTR3410_2012_512_PARAM_SET_A, ID_GOSTR3410_2012_512_PARAM_SET_B,
    ID_GOSTR3410_2012_512_PARAM_SET_C, ID_GOSTR3410_2012_512_TEST_PARAM_SET
} from "./const.js";
import { getMinHashLength, mapHashToField } from "@noble/curves/abstract/modular.js";
import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { createKeygen, type AffinePoint } from "@noble/curves/abstract/curve.js";
import type { ECDSA, SignOpts } from "../types.js";
import { createStreebogHmacDrbg } from "./drbg.js";
import { ahash, type CHash, type Hash } from "@noble/hashes/utils.js";

/** Swap `x` and `y` in point bytes */
const swapPoint = (point: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    point.subarray(point.length / 2),
    point.subarray(0, point.length / 2),
);

/** Creates GOST R 34.10-2012 (2001) signing interface */
export const gost3410 = (parameters: GostCurveParameters): ECDSA => {
    const Point = weierstrass(parameters), { Fp, Fn, BASE } = Point;
    const lengths = Object.freeze({
        secretKey: Fn.BYTES,
        publicKey: 1 + Fp.BYTES,
        publicKeyUncompressed: 1 + 2 * Fp.BYTES,
        publicKeyHasPrefix: true,
        signature: 2 * Fn.BYTES,
        seed: Math.max(getMinHashLength(Fn.ORDER), 16)
    });
    const drbg = createStreebogHmacDrbg(Point.Fn);

    const prepareHash = (digest: TArg<Uint8Array>): bigint =>
        Fn.create(bytesToNumberBE(digest)) || 1n;

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
     *   e = m mod n (if e=0, let e=1)
     *   k = streebog_hmac_drbg(d, m)
     *   (x, y) = G × k
     *   r = x mod n
     *   s = (r ⋅ d + k ⋅ e) mod n
     * ```
     */
    const sign = (secretKey: TArg<Uint8Array>, digest: TArg<Uint8Array>, opts?: SignOpts) => {
        abytes(secretKey, undefined, "secretKey");
        abytes(digest, undefined, "digest");
        const { rand, extraEntropy } = opts ?? {};
        const d = Fn.fromBytes(secretKey);
        if(!Fn.isValidNot0(d)) throw new Error("Invalid private key");

        const k = rand ? Fn.create(bytesToNumberBE(rand)) : drbg(d, digest, extraEntropy);
        if(rand && k == 0n) throw new Error("Invalid rand specified");

        const r = Fn.create(BASE.multiply(k).x),
            s = Fn.add(Fn.mul(r, d), Fn.mul(k, prepareHash(digest)));

        return concatBytes(Fn.toBytes(r), Fn.toBytes(s));
    }

    /**
     * Verifies a signature against message hash and public key.
     * 
     * ```
     * verify(P, m, r, s) where
     *   e = m mod n (if e=0, let e=1)
     *   v = e^-1 mod n
     *   z1 = s ⋅ v mod n
     *   z2 = -r ⋅ v mod n
     *   R = (z1 × G + z2 × P).x mod n
     *   R == r
     * ```
     */
    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>
    ) => {
        abytes(publicKey, undefined, "publicKey");
        abytes(digest, undefined, "digest");
        abytes(signature, lengths.signature, "signature");
        const r = Fn.fromBytes(signature.subarray(0, Fn.BYTES)),
            s = Fn.fromBytes(signature.subarray(Fn.BYTES));
        if(!Fn.isValidNot0(r) || !Fn.isValidNot0(s)) return false;

        const v = Fn.inv(prepareHash(digest));
        const z1 = Fn.mul(s, v), z2 = Fn.mul(Fn.neg(r), v);

        try {
            const R = BASE.mulAddUnsafe(z1, Point.fromBytes(publicKey), z2);
            return Fn.create(R.x) === r;
        } catch { return false; }
    }

    /**
     * Key agreement function (ECDH)
     * 
     * Computes hashed shared point from secret key A and public key B.
     * @param hash Hash function to use (GOST R 34.11-94, Streebog-256, Streebog-512)
     * @param ukm User keying material (aka salt, VKO-factor)
     */
    const getSharedSecret = (
        hash: CHash<Hash<any>>,
        secretKeyA: TArg<Uint8Array>,
        publicKeyB: TArg<Uint8Array>,
        ukm: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        ahash(hash);
        abytes(secretKeyA, undefined, "secretKeyA");
        abytes(publicKeyB, undefined, "publicKeyB");
        abytes(ukm, undefined, "ukm");
        const key = Point.fromBytes(publicKeyB)
        .multiply(Fn.fromBytes(secretKeyA))
        .multiply(Fn.mul(parameters.h, bytesToNumberBE(ukm)));

        const kx = Fp.toBytes(key.x).reverse(),
            ky = Fp.toBytes(key.y).reverse();

        return hash.create().update(kx).update(ky).digest();
    }

    const keygen = createKeygen(
        (seed?: TArg<Uint8Array>) => mapHashToField(
            abytes(seed ?? randomBytes(lengths.seed), lengths.seed, 'seed'), 
            Fn.ORDER
        ),
        getPublicKey
    );

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

    const utils = Object.freeze({ uv2xy, xy2uv, swapPoint, parameters });

    return Object.freeze({
        Point, getPublicKey, getSharedSecret,
        sign, verify,
        keygen, lengths, utils
    });
}

export type { GostCurveParameters } from "./const.js";
/** GOST R 34.10-2001 CryptoCom curve */
export const gost2001CC = gost3410(ID_GOSTR3410_2001_PARAM_SET_CC);
/** GOST R 34.10-2001 test curve */
export const gost2001Test = gost3410(ID_GOSTR3410_2001_TEST_PARAM_SET);
/** GOST R 34.10-2012 256 bit `A` curve */
export const gost256A = gost3410(ID_GOSTR3410_2012_256_PARAM_SET_A);
/** GOST R 34.10-2012 256 bit `B` curve (aka CryptoPro `A` and `X-A`) */
export const gost256B = gost3410(ID_GOSTR3410_2012_256_PARAM_SET_B);
/** GOST R 34.10-2012 256 bit `C` curve (aka CryptoPro `B`) */
export const gost256C = gost3410(ID_GOSTR3410_2012_256_PARAM_SET_C);
/** GOST R 34.10-2012 256 bit `D` curve (aka CryptoPro `C` and `X-B`) */
export const gost256D = gost3410(ID_GOSTR3410_2012_256_PARAM_SET_D);
/** GOST R 34.10-2012 512 bit test curve */
export const gost512Test = gost3410(ID_GOSTR3410_2012_512_TEST_PARAM_SET);
/** GOST R 34.10-2012 512 bit `A` curve */
export const gost512A = gost3410(ID_GOSTR3410_2012_512_PARAM_SET_A);
/** GOST R 34.10-2012 512 bit `B` curve */
export const gost512B = gost3410(ID_GOSTR3410_2012_512_PARAM_SET_B);
/** GOST R 34.10-2012 512 bit `C` curve */
export const gost512C = gost3410(ID_GOSTR3410_2012_512_PARAM_SET_C);

/** Standard curves */
export const CURVES = {
    gost2001CC, gost2001Test,
    gost256A, gost256B, gost256C, gost256D,
    gost512Test, gost512A, gost512B, gost512C
}