import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma, magmaSboxes } from "../magma";
import { cbc } from "./cbc";

describe("[CBC] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const iv = hexToBytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
        const pt = hexToBytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
        const ct = hexToBytes("689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970");
        const cipher = new Kuznyechik(key);
        const mode = cbc(cipher, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});

describe("[CBC] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const iv = hexToBytes("1234567890abcdef234567890abcdef134567890abcdef12")
        const pt = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        const ct = hexToBytes("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667");
        const cipher = new Magma(key);
        const mode = cbc(cipher, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const iv = hexToBytes("1234567890abcdef234567890abcdef134567890abcdef12")
        const pt = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        const ct = hexToBytes("cf9506a890323fd327dbf50b065dffbdd7fcb975b73b0dd83de52fb6c1a0eb1f");
        const cipher = new Magma(key, magmaSboxes.ID_GOST_28147_89_TEST_PARAM_SET, true);
        const mode = cbc(cipher, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});