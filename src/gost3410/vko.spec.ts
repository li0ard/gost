import { hexToBytes } from "@noble/curves/utils.js";
import { describe, test, expect } from "bun:test";
import { gost2001Test, gost512A } from "./index.js";
import { gost341194 } from "../gost341194/index.js";
import { streebog256, streebog512 } from "../streebog/index.js";

test("[SIGN] VKO 2001", () => {
    const ukm = hexToBytes("5172be25f852a233").reverse();
    const prv1 = hexToBytes("1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928").reverse();
    const prv2 = hexToBytes("5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473").reverse();
    const kek = hexToBytes("ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6");
    const pub1 = gost2001Test.getPublicKey(prv1);
    const pub2 = gost2001Test.getPublicKey(prv2);
    expect(gost2001Test.getSharedSecret(gost341194, prv1, pub2, ukm)).toStrictEqual(kek);
    expect(gost2001Test.getSharedSecret(gost341194, prv2, pub1, ukm)).toStrictEqual(kek);
});

describe("[SIGN] VKO 2012", () => {
    const ukm = hexToBytes("1d80603c8544c727").reverse();
    const prv1 = hexToBytes("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667").reverse();
    const prv2 = hexToBytes("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db").reverse();
    const pub1 = gost512A.getPublicKey(prv1);
    const pub2 = gost512A.getPublicKey(prv2);

    test("256 bit", () => {
        const kek = hexToBytes("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221");
        expect(gost512A.getSharedSecret(streebog256, prv1, pub2, ukm)).toStrictEqual(kek);
        expect(gost512A.getSharedSecret(streebog256, prv2, pub1, ukm)).toStrictEqual(kek);
    });

    test("512 bit", () => {
        const kek = hexToBytes("79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf");
        expect(gost512A.getSharedSecret(streebog512, prv1, pub2, ukm)).toStrictEqual(kek);
        expect(gost512A.getSharedSecret(streebog512, prv2, pub1, ukm)).toStrictEqual(kek);
    });
});