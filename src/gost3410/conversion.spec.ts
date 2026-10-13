import { describe, test, expect } from "bun:test";
import { gost256A, gost512C } from "./index.js";
import type { ECDSA } from "../types.js";
import type { AffinePoint } from "@noble/curves/abstract/weierstrass.js";

const processTest = (
    signer: ECDSA,
    point: AffinePoint<bigint>,
    point2: AffinePoint<bigint>
) => {
    const result1 = signer.utils.uv2xy(point);
    expect(result1.x).toStrictEqual(point2.x);
    expect(result1.y).toStrictEqual(point2.y);

    const result2 = signer.utils.xy2uv(point2);
    expect(result2.x).toStrictEqual(point.x);
    expect(result2.y).toStrictEqual(point.y);
}

describe("[SIGN] Point conversion", () => {
    test("256 bit", () => processTest(
        gost256A,
        {
            x: 0x0dn,
            y: 0x60CA1E32AA475B348488C38FAB07649CE7EF8DBE87F22E81F92B2592DBA300E7n
        },
        {
            x: gost256A.utils.parameters.Gx,
            y: gost256A.utils.parameters.Gy
        }
    ));

    test("512 bit", () => processTest(
        gost512C,
        {
            x: 0x12n,
            y: 0x469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B38669522DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3Dn
        },
        {
            x: gost512C.utils.parameters.Gx,
            y: gost512C.utils.parameters.Gy
        }
    ));
});