import { hexToBytes } from "@noble/curves/utils.js";
import { describe, test, expect } from "bun:test";
import { _magma, _magma2 } from "../modes/_test_utils.test";

describe("[CORE] Magma", () => {
    test("#1 (GOST R 34.12-2015)", () => {
        const pt = hexToBytes("fedcba9876543210");
        const ct = hexToBytes("4ee901e5c2d8ca3d");

        expect(_magma.encrypt(pt)).toStrictEqual(ct);
        expect(_magma.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2 (GOST 28147-89)", () => {
        const pt = hexToBytes("0706050403020100");
        const ct = hexToBytes("4b8c4c9815f24aea");

        expect(_magma2.encrypt(pt)).toStrictEqual(ct);
        expect(_magma2.decrypt(ct)).toStrictEqual(pt);
    });
});