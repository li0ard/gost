import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { streebog256hmac, streebog512hmac, gost341194hmac } from "./hmac";

describe("[HMAC] Streebog", () => {
    const key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const msg = hexToBytes("0126bdb87800af214341456563780100");

    test("#1", () => {
        const expected = hexToBytes("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");
        expect(streebog256hmac(key, msg)).toStrictEqual(expected);
    });

    test("#2", () => {
        const expected = hexToBytes("a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6");
        expect(streebog512hmac(key, msg)).toStrictEqual(expected);
    });

    test("#3", () => {
        const expected = hexToBytes("bad70b61c41095bc47e1141cfaed42726a5ceebd62ce75dbbb9ad76cda9f72f7");
        expect(gost341194hmac(key, msg)).toStrictEqual(expected);
    });
});