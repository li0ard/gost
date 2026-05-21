import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma, magmaSboxes } from "../magma";
import { cfb } from "./cfb";

describe("[CFB] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const iv = hexToBytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
        const pt = hexToBytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
        const ct = hexToBytes("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1");
        const cipher = new Kuznyechik(key);
        const mode = cfb(cipher, iv);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});

describe("[CFB] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const iv = hexToBytes("1234567890abcdef234567890abcdef1");
        const pt = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        const ct = hexToBytes("db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505");
        const cipher = new Magma(key);
        const mode = cfb(cipher, iv);

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
