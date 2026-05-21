import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma } from "../magma";
import { ofb } from "./ofb";

describe("[OFB] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const iv = hexToBytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")
        const pt = hexToBytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
        const ct = hexToBytes("81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150");
        const cipher = new Kuznyechik(key);
        const mode = ofb(cipher, iv);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});

describe("[OFB] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const iv = hexToBytes("1234567890abcdef234567890abcdef1")
        const pt = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        const ct = hexToBytes("db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05");
        const cipher = new Magma(key);
        const mode = ofb(cipher, iv);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});