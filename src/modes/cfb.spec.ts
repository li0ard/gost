import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Magma, magmaSboxes } from "../magma";
import { cfb } from "./cfb";
import { _kuznyechik, _magma, IV_KUZNYECHIK, IV_MAGMA, PT_KUZNYECHIK, PT_MAGMA } from "./_test_utils.test";

describe("[CFB] Kuznyechik", () => {
    test("#1", () => {
        const pt = PT_KUZNYECHIK;
        const ct = hexToBytes("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1");
        const mode = cfb(_kuznyechik, IV_KUZNYECHIK);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});

describe("[CFB] Magma", () => {
    test("#1", () => {
        const pt = PT_MAGMA;
        const ct = hexToBytes("db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505");
        const mode = cfb(_magma, IV_MAGMA);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2", () => {
        const key = hexToBytes("75713134B60FEC45A607BB83AA3746AF4FF99DA6D1B53B5B1B402A1BAA030D1B");
        const iv = hexToBytes("0102030405060708");
        const pt = hexToBytes("112233445566778899AABBCCDD800000");
        const ct = hexToBytes("6EE84586DD2BCA0CAD3616940E164242");
        const cipher = new Magma(key, magmaSboxes.ID_GOSTR_3411_94_TEST_PARAM_SET, true);
        const mode = cfb(cipher, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});
