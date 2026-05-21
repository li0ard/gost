import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma } from "../magma";
import { mgm } from "./mgm";

describe("[MGM] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        const iv = hexToBytes("1122334455667700FFEEDDCCBBAA9988");
        const aad = hexToBytes("0202020202020202010101010101010104040404040404040303030303030303EA0505050505050505");
        const pt = hexToBytes("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011AABBCC");
        const ct = hexToBytes("A9757B8147956E9055B8A33DE89F42FC8075D2212BF9FD5BD3F7069AADC16B39497AB15915A6BA85936B5D0EA9F6851CC60C14D4D3F883D0AB94420695C76DEB2C7552CF5D656F40C34F5C46E8BB0E29FCDB4C");
        const cipher = new Kuznyechik(key);
        const mode = mgm(cipher, iv);

        expect(mode.seal(pt, aad)).toStrictEqual(ct);
        expect(mode.open(ct, aad)).toStrictEqual(pt);
    });
});

describe("[MGM] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const iv = hexToBytes("12DEF06B3C130A59");
        const aad = hexToBytes("01010101010101010202020202020202030303030303030304040404040404040505050505050505EA");
        const pt = hexToBytes("FFEEDDCCBBAA998811223344556677008899AABBCCEEFF0A001122334455667799AABBCCEEFF0A001122334455667788AABBCCEEFF0A00112233445566778899AABBCC");
        const ct = hexToBytes("C795066C5F9EA03B85113342459185AE1F2E00D6BF2B785D940470B8BB9C8E7D9A5DD3731F7DDC70EC27CB0ACE6FA57670F65C646ABB75D547AA37C3BCB5C34E03BB9CA7928069AA10FD10");
        const cipher = new Magma(key);
        const mode = mgm(cipher, iv);

        expect(mode.seal(pt, aad)).toStrictEqual(ct);
        expect(mode.open(ct, aad)).toStrictEqual(pt);
    });
});