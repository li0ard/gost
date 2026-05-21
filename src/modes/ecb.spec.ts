import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma, magmaSboxes } from "../magma";
import { ecb } from "./ecb";

describe("[ECB] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const pt = hexToBytes("1122334455667700ffeeddccbbaa99881122334455667700ffeeddccbbaa9988");
        const ct = hexToBytes("7f679d90bebc24305a468d42b9d4edcd7f679d90bebc24305a468d42b9d4edcd");
        const cipher = new Kuznyechik(key);
        const mode = ecb(cipher);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});

describe("[ECB] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const pt = hexToBytes("fedcba9876543210fedcba9876543210");
        const ct = hexToBytes("4ee901e5c2d8ca3d4ee901e5c2d8ca3d");
        const cipher = new Magma(key);
        const mode = ecb(cipher);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });

    test("#2", () => {
        const key = hexToBytes("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd");
        const pt = hexToBytes("07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a191827262524232221202f2e2d2c2b2a292837363534333231303f3e3d3c3b3a393847464544434241404f4e4d4c4b4a494857565554535251505f5e5d5c5b5a595867666564636261606f6e6d6c6b6a696877767574737271707f7e7d7c7b7a797887868584838281808f8e8d8c8b8a898897969594939291909f9e9d9c9b9a9998a7a6a5a4a3a2a1a0afaeadacabaaa9a8b7b6b5b4b3b2b1b0bfbebdbcbbbab9b8c7c6c5c4c3c2c1c0cfcecdcccbcac9c8d7d6d5d4d3d2d1d0dfdedddcdbdad9d8e7e6e5e4e3e2e1e0efeeedecebeae9e8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8");
        const ct = hexToBytes("4b8c4c9815f24aea1ec35709b3bc2ed1e0d1f222652d5918f7dffc804bde5c6846537553a7460dec051f1bd30a631ab778c443e05d3ea40e2d7e23a91bc902bc210c84cb0d0a07c87bd0fbb51a14045ca25397712e5cc28f393f6f52f230264e8ce0d101756ddcd303791ecad5c10e12530a78e20ab11cea3af855b97ce10bbaa0c896eb505ad36043a30f98dbd9506d6391af0140e9755a465c1f194a0b899bc4f6f8f52f873ffa26d4f825ba1f9882fc26af2dc0f9c45849fa09800262a4342dcb5a6bab615d08d426e00813d62e022a37e8d0cf36f1c7c03f9b2160bd292d2e01484ef88f20168abf82dc327aa31869d150593191f26c5a5fca589ab22db2");
        const cipher = new Magma(key, magmaSboxes.ID_GOST_28147_89_TEST_PARAM_SET, true);
        const mode = ecb(cipher);

        expect(mode.encrypt(pt)).toStrictEqual(ct);
        expect(mode.decrypt(ct)).toStrictEqual(pt);
    });
});