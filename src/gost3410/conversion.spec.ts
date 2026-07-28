import { describe, test, expect } from "bun:test";
import { gost256A, gost512C } from ".";

describe("[SIGN] Point conversion (256 bit)", () => {
    const c = gost256A;
    const point = {
        x: 0x0dn,
        y: 0x60CA1E32AA475B348488C38FAB07649CE7EF8DBE87F22E81F92B2592DBA300E7n
    }
    const point2 = {
        x: 0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28n,
        y: 0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5Cn
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
    const c = gost512C;
    const point = {
        x: 0x12n,
        y: 0x469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B38669522DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3Dn
    }
    const point2 = {
        x: 0xE2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148n,
        y: 0xF5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40Fn
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