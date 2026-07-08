import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Gost341194, gost3431195 } from ".";
import { magmaSboxes } from "../magma";

describe("[HASH] GOST R 34.11-94", () => {
    const input = new TextEncoder().encode("This is message, length=32 bytes");
    const input2 = new TextEncoder().encode("Suppose the original message has length = 50 bytes");
    const input3 = new Uint8Array(256).fill(0xff);
    test("#1", () => {
        const expected = hexToBytes("b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa");
        expect(new Gost341194(input, magmaSboxes.ID_GOSTR_3411_94_TEST_PARAM_SET).digest()).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208");
        expect(new Gost341194(input2, magmaSboxes.ID_GOSTR_3411_94_TEST_PARAM_SET).digest()).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("8df69d0619119294accb7bb73fad2daf46383058aba12b3e718cb27dc14ae94d");
        expect(gost3431195(input3)).toStrictEqual(expected);
    });
});