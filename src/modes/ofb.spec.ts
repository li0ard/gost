import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { ofb } from "./ofb";
import { _kuznyechik, _magma, IV_KUZNYECHIK, IV_MAGMA, PT_KUZNYECHIK, PT_MAGMA } from "./_test_utils.test";

describe("[OFB] Kuznyechik", () => {
    test("#1", () => {
        const pt = PT_KUZNYECHIK;
        const ct = hexToBytes("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150");
        const mode = ofb(_kuznyechik, IV_KUZNYECHIK);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});

describe("[OFB] Magma", () => {
    test("#1", () => {
        const pt = PT_MAGMA;
        const ct = hexToBytes("db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05");
        const mode = ofb(_magma, IV_MAGMA);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});