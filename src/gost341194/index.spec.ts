import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { gost341194, gost3431195 } from ".";
import { magmaSboxes } from "../magma";

describe("[HASH] GOST R 34.11-94", () => {
    const input = new TextEncoder().encode("Suppose the original message has length = 50 bytes");
    const input2 = new Uint8Array(256).fill(0xff);
    test("#1", () => {
        const expected = hexToBytes("c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011");

        expect(gost341194(input)).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208");

        expect(gost341194(input, magmaSboxes.ID_GOSTR_3411_94_TEST_PARAM_SET)).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("8df69d0619119294accb7bb73fad2daf46383058aba12b3e718cb27dc14ae94d");

        expect(gost3431195(input2)).toStrictEqual(expected);
    });
});