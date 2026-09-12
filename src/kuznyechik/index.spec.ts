import { hexToBytes } from "@noble/curves/utils.js";
import { describe, test, expect } from "bun:test";
import { _kuznyechik } from "../modes/_test_utils.test";

describe("[CORE] Kuznyechik (GOST R 34.12-2015)", () => {
    test("#1", () => {
        const pt = hexToBytes("1122334455667700ffeeddccbbaa9988");
        const ct = hexToBytes("7f679d90bebc24305a468d42b9d4edcd");

        expect(_kuznyechik.encrypt(pt)).toStrictEqual(ct);
        expect(_kuznyechik.decrypt(ct)).toStrictEqual(pt);
    });
});