import { describe, test, expect } from "bun:test";
import { gost3410, ID_GOSTR3410_2012_256_PARAM_SET_A, ID_GOSTR3410_2012_512_PARAM_SET_C } from ".";

describe("[SIGN] Point conversion (256 bit)", () => {
    const c = gost3410(ID_GOSTR3410_2012_256_PARAM_SET_A);
    const point = {
        x: 0x0dn,
        y: 0x60CA1E32AA475B348488C38FAB07649CE7EF8DBE87F22E81F92B2592DBA300E7n
    }
    const point2 = {
        x: ID_GOSTR3410_2012_256_PARAM_SET_A.Gx,
        y: ID_GOSTR3410_2012_256_PARAM_SET_A.Gy
    }
    test("(u,v) -> (x,y)", () => {
        const result = c.utils.uv2xy(point);
        expect(result.x).toStrictEqual(point2.x);
        expect(result.y).toStrictEqual(point2.y);
    });

    test("(x,y) -> (u,v)", () => {
        const result = c.utils.xy2uv(point2);
        expect(result.x).toStrictEqual(point.x);
        expect(result.y).toStrictEqual(point.y);
    });
});

describe("[SIGN] Point conversion (512 bit)", () => {
    const c = gost3410(ID_GOSTR3410_2012_512_PARAM_SET_C);
    const point = {
        x: 0x12n,
        y: 0x469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B38669522DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3Dn
    }
    const point2 = {
        x: ID_GOSTR3410_2012_512_PARAM_SET_C.Gx,
        y: ID_GOSTR3410_2012_512_PARAM_SET_C.Gy
    }
    test("(u,v) -> (x,y)", () => {
        const result = c.utils.uv2xy(point);
        expect(result.x).toStrictEqual(point2.x);
        expect(result.y).toStrictEqual(point2.y);
    });

    test("(x,y) -> (u,v)", () => {
        const result = c.utils.xy2uv(point2);
        expect(result.x).toStrictEqual(point.x);
        expect(result.y).toStrictEqual(point.y);
    });
});