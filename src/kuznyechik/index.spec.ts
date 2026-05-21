import { hexToBytes } from "@noble/curves/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from ".";

describe("[CORE] Kuznyechik (GOST R 34.12-2015)", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const pt = hexToBytes("1122334455667700ffeeddccbbaa9988");
        const ct = hexToBytes("7f679d90bebc24305a468d42b9d4edcd");
        const cipher = new Kuznyechik(key);

        expect(cipher.encrypt(pt)).toStrictEqual(ct);
        expect(cipher.decrypt(ct)).toStrictEqual(pt);
    });
});