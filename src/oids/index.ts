/**
 * Implementation of ObjectIdentifier's (OID) registry for curves and hash algorithms
 * @module
 */
import { CURVES } from "../gost3410/index.js";
import { gost341194 } from "../gost341194/index.js";
import { streebog256, streebog512 } from "../streebog/index.js";
import type { CipherOrHashFunctionWrapper, Signer } from "../types.js";

const HASHES_OID: Record<string, CipherOrHashFunctionWrapper> = {
    "1.2.643.7.1.1.2.1": gost341194,
    "1.2.643.7.1.1.2.2": streebog256,
    "1.2.643.7.1.1.2.3": streebog512
}

/** Get curve parameters by OID */
export const getCurveByOid = (oid: string): Signer | undefined => {
    for (const [_, c] of Object.entries(CURVES))
        if (c.utils.parameters.oids?.includes(oid)) return c;
}

/** Get hash function by OID */
export const getHashByOid = (oid: string): CipherOrHashFunctionWrapper | undefined => HASHES_OID[oid];
