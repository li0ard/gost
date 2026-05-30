import { Field } from "@noble/curves/abstract/modular.js";
import { weierstrass } from "@noble/curves/abstract/weierstrass.js";
import { gost341194 } from "../gost341194";
import { streebog256, streebog512 } from "../streebog/index.js";
import type { GostCurveParameters } from "./const.js";
import { bytesToNumberBE, concatBytes, numberToBytesLE, type TArg, type TRet } from "@noble/curves/utils.js";

/**
 * Key agreement function
 * @param parameters Curve parameters
 * @param prv Private key
 * @param pub Public key
 * @param ukm User keying material (aka salt, VKO-factor)
 * @returns {TRet<Uint8Array>} Shared key (Not hashed)
 */
export const kek = (
    parameters: GostCurveParameters,
    prv: TArg<Uint8Array>,
    pub: TArg<Uint8Array>,
    ukm: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const Fn = Field(parameters.n);
    const key = weierstrass(parameters).fromBytes(pub)
        .multiply(bytesToNumberBE(prv))
        .multiply(Fn.mulN(parameters.h, bytesToNumberBE(ukm)));
    return concatBytes(numberToBytesLE(key.x, parameters.length), numberToBytesLE(key.y, parameters.length));
}

/**
 * Key agreement function over GOST R 34.11-94 hash
 * @param parameters Curve parameters
 * @param prv Private key
 * @param pub Public key
 * @param ukm User keying material (aka salt, VKO-factor)
 * @returns {TRet<Uint8Array>} Shared key
 */
export const kek_34102001 = (
    parameters: GostCurveParameters,
    prv: TArg<Uint8Array>,
    pub: TArg<Uint8Array>,
    ukm: TArg<Uint8Array>
): TRet<Uint8Array> => gost341194(kek(parameters, prv, pub, ukm));

/**
 * Key agreement function over Streebog (GOST R 34.11-2012) 256 bit hash
 * @param parameters Curve parameters
 * @param prv Private key
 * @param pub Public key
 * @param ukm User keying material (aka salt, VKO-factor)
 * @returns {TRet<Uint8Array>} Shared key
 */
export const kek_34102012256 = (
    parameters: GostCurveParameters,
    prv: TArg<Uint8Array>,
    pub: TArg<Uint8Array>,
    ukm: TArg<Uint8Array>
): TRet<Uint8Array> => streebog256(kek(parameters, prv, pub, ukm));

/**
 * Key agreement function over Streebog (GOST R 34.11-2012) 512 bit hash
 * @param parameters Curve parameters
 * @param prv Private key
 * @param pub Public key
 * @param ukm User keying material (aka salt, VKO-factor)
 * @returns {TRet<Uint8Array>} Shared key
 */
export const kek_34102012512 = (
    parameters: GostCurveParameters,
    prv: TArg<Uint8Array>,
    pub: TArg<Uint8Array>,
    ukm: TArg<Uint8Array>
): TRet<Uint8Array> => streebog512(kek(parameters, prv, pub, ukm));