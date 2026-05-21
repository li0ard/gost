import { hexToBytes } from "@noble/curves/utils.js";
import { describe, test, expect } from "bun:test";
import { Magma, magmaSboxes } from ".";

describe("[CORE] Magma", () => {
    test("#1 (GOST R 34.12-2015)", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const pt = hexToBytes("fedcba9876543210");
        const ct = hexToBytes("4ee901e5c2d8ca3d");
        const cipher = new Magma(key);

        expect(cipher.encrypt(pt)).toStrictEqual(ct);
        expect(cipher.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2 (GOST 28147-89)", () => {
        const key = hexToBytes("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd");
        const pt = hexToBytes("0706050403020100");
        const ct = hexToBytes("4b8c4c9815f24aea");
        const cipher = new Magma(key, magmaSboxes.ID_GOST_28147_89_TEST_PARAM_SET, true);

        expect(cipher.encrypt(pt)).toStrictEqual(ct);
        expect(cipher.decrypt(ct)).toStrictEqual(pt);
    });
});