import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { cpkdf, gost341194pbkdf2, kdf_gostr3411_2012_256, kdf_tree_gostr3411_2012_256, streebog512pbkdf2 } from "./kdf";

const password = new TextEncoder().encode("password");
const salt = new TextEncoder().encode("salt");

describe("[KDF] Streebog", () => {
    const key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const label = hexToBytes("26bdb878");
    const seed = hexToBytes("af21434145656378");

    test("kdf_gostr3411_2012_256", () => {
        const expected = hexToBytes("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");
        expect(kdf_gostr3411_2012_256(key, label, seed)).toStrictEqual(expected);
    });

    test("kdf_tree_gostr3411_2012_256", () => {
        const expected = hexToBytes("22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b");
        const expected2 = hexToBytes("074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9");

        const keymat = kdf_tree_gostr3411_2012_256(key, label, seed, 2);
        expect(keymat[0]).toStrictEqual(expected);
        expect(keymat[1]).toStrictEqual(expected2);
    });

    test("PBKDF2", () => {
        const expected = hexToBytes("5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4d34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de");
        expect(streebog512pbkdf2(password, salt, 2, 64)).toStrictEqual(expected);
    });

    test("CPKDF", () => {
        const pass = new TextEncoder().encode("qawsqaws");
        const salt = hexToBytes("98e4f49415555d8ab20567a0");
        const expected  = hexToBytes("b551b39608787399ba85c59c68906b8f83c289ccee3c6141700dfc75ec0fd9f5");

        expect(cpkdf(pass, salt)).toStrictEqual(expected);
    });
});

describe("[KDF] GOST R 34.11-94", () => {
    test("PBKDF2", () => {
        const expected = hexToBytes("990dfa2bd965639ba48b07b792775df79f2db34fef25f274378872fed7ed1bb3");
        expect(gost341194pbkdf2(password, salt, 2, 32)).toStrictEqual(expected);
    });
});