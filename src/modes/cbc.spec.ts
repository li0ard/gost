import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Magma, magmaSboxes } from "../magma";
import { cbc } from "./cbc";
import { _kuznyechik, _magma, IV_KUZNYECHIK, KEY_MAGMA, PT_KUZNYECHIK, PT_MAGMA } from "./_test_utils.test";

describe("[CBC] Kuznyechik", () => {
    test("#1", () => {
        const pt = PT_KUZNYECHIK;
        const ct = hexToBytes("689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970");
        const mode = cbc(_kuznyechik, IV_KUZNYECHIK);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});

describe("[CBC] Magma", () => {
    const iv = hexToBytes("1234567890abcdef234567890abcdef134567890abcdef12")
    const pt = PT_MAGMA;
    test("#1", () => {
        const ct = hexToBytes("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667");
        const mode = cbc(_magma, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2", () => {
        const ct = hexToBytes("cf9506a890323fd327dbf50b065dffbdd7fcb975b73b0dd83de52fb6c1a0eb1f");
        const cipher = new Magma(KEY_MAGMA, magmaSboxes.ID_GOST_28147_89_TEST_PARAM_SET, true);
        const mode = cbc(cipher, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});