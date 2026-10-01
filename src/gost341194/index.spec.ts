import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { gost341194 } from ".";

describe("[HASH] GOST R 34.11-94", () => {
    test("#1", () => {
        const expected = hexToBytes("2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb");
        expect(gost341194(new TextEncoder().encode("This is message, length=32 bytes"))).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011");
        expect(gost341194(new TextEncoder().encode("Suppose the original message has length = 50 bytes"))).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("1c4ac7614691bbf427fa2316216be8f10d92edfd37cd1027514c1008f649c4e8");
        expect(gost341194(new Uint8Array(128).fill(0x55))).toStrictEqual(expected);
    });

    test("#4", () => {
        const expected = hexToBytes("b9cd35b9a7a4b3d17ce4f8772630d765bd278164516d2227e7f29128bf236919");
        expect(gost341194(hexToBytes("d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000002400000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))).toStrictEqual(expected);
    });
});