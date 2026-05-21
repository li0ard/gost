import { describe, test, expect } from "bun:test";
import { ID_GOSTR3410_2012_256_PARAM_SET_A, ID_GOSTR3410_2012_512_PARAM_SET_C, uv2xy, xy2uv } from ".";

describe("[SIGN] Point conversion (256 bit)", () => {
    const c = ID_GOSTR3410_2012_256_PARAM_SET_A;
    test("(u,v) -> (x,y)", () => {
        const point = {
            x: 0x0dn,
            y: 0x60CA1E32AA475B348488C38FAB07649CE7EF8DBE87F22E81F92B2592DBA300E7n
        }
        const result = uv2xy(c, point);
        expect(result.x).toStrictEqual(c.Gx);
        expect(result.y).toStrictEqual(c.Gy);
    });

    test("(x,y) -> (u,v)", () => {
        const point = {
            x: c.Gx,
            y: c.Gy
        }
        const result = xy2uv(c, point);
        expect(result.x).toStrictEqual(0x0dn);
        expect(result.y).toStrictEqual(0x60CA1E32AA475B348488C38FAB07649CE7EF8DBE87F22E81F92B2592DBA300E7n);
    });
});

describe("[SIGN] Point conversion (512 bit)", () => {
    const c = ID_GOSTR3410_2012_512_PARAM_SET_C;
    test("(u,v) -> (x,y)", () => {
        const point = {
            x: 0x12n,
            y: 0x469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B38669522DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3Dn
        }
        const result = uv2xy(c, point);
        expect(result.x).toStrictEqual(c.Gx);
        expect(result.y).toStrictEqual(c.Gy);
    });

    test("(x,y) -> (u,v)", () => {
        const point = {
            x: c.Gx,
            y: c.Gy
        }
        const result = xy2uv(c, point);
        expect(result.x).toStrictEqual(0x12n);
        expect(result.y).toStrictEqual(0x469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B38669522DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3Dn);
    });
});