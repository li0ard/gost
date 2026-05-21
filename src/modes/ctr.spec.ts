import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma, magmaSboxes } from "../magma";
import { cnt, ctr } from "./ctr";

describe("[CTR] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const iv = hexToBytes("1234567890abcef0");
        const pt = hexToBytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
        const ct = hexToBytes("f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73");
        const cipher = new Kuznyechik(key);
        const mode = ctr(cipher, iv);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});

describe("[CTR] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const iv = hexToBytes("12345678");
        const pt = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        const ct = hexToBytes("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d");
        const cipher = new Magma(key);
        const mode = ctr(cipher, iv);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});

describe("[CNT] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd");
        const iv = hexToBytes("0201010101010101");
        const pt = hexToBytes("07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a191827262524232221202f2e2d2c2b2a292837363534333231303f3e3d3c3b3a393847464544434241404f4e4d4c4b4a494857565554535251505f5e5d5c5b5a595867666564636261606f6e6d6c6b6a696877767574737271707f7e7d7c7b7a797887868584838281808f8e8d8c8b8a898897969594939291909f9e9d9c9b9a9998a7a6a5a4a3a2a1a0afaeadacabaaa9a8b7b6b5b4b3b2b1b0bfbebdbcbbbab9b8c7c6c5c4c3c2c1c0cfcecdcccbcac9c8d7d6d5d4d3d2d1d0dfdedddcdbdad9d8e7e6e5e4e3e2e1e0efeeedecebeae9e8f7f6f5f4f3f2f1f0fffefdfcfb");
        const ct = hexToBytes("4a5e376ca112d35509131a21acfbb21e8c249b57206846d5232a263512565c692a2fd1abbd45dc3a1aa45764d5e4696db48bf154783b108f7a4b32e0e84cbf032437956a55a8ce6f956212f679e6f01b86ef363605d86f10a1410507f8faa40b172c71bc8bcbcf3d7418320b1cd29e75ba3e61e16196d0ee8ff29a5eb77a15aa4e1e777c99e14113f46039464c35de95cc4fd5afd14d841a45c72af22cc0b794a308b91296b597993ab70c1456b9cb4944a993a9fb19108c6a68e87b0657f0ef8844a6d298bed407413745a6713676694b75153390296e33cb963978192e96f3494c893da1868200cebd542965001d1613c3fe1f8c5563091fcdd428ca");
        const cipher = new Magma(key, magmaSboxes.ID_GOST_28147_89_TEST_PARAM_SET, true);
        const mode = cnt(cipher, iv);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});

describe("[CTR-ACPKM] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        const iv = hexToBytes("1234567890ABCEF0");
        const pt = hexToBytes("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A001133445566778899AABBCCEEFF0A001122445566778899AABBCCEEFF0A001122335566778899AABBCCEEFF0A0011223344");
        const ct = hexToBytes("F195D8BEC10ED1DBD57B5FA240BDA1B885EEE733F6A13E5DF33CE4B33C45DEE44BCEEB8F646F4C55001706275E85E800587C4DF568D094393E4834AFD0805046CF30F57686AEECE11CFC6C316B8A896EDFFD07EC813636460C4F3B743423163E6409A9C282FAC8D469D221E7FBD6DE5D");
        const cipher = new Kuznyechik(key);
        const mode = ctr(cipher, iv, true);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});

describe("[CTR-ACPKM] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        const iv = hexToBytes("12345678");
        const pt = hexToBytes("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899");
        const ct = hexToBytes("2AB81DEEEB1E4CAB68E104C4BD6B94EAC72C67AF6C2E5B6B0EAFB61770F1B32EA1AE71149EED1382ABD467180672EC6F84A2F15B3FCA72C1");
        const cipher = new Magma(key);
        const mode = ctr(cipher, iv, true);

        expect(mode.crypt(pt)).toStrictEqual(ct);
        expect(mode.crypt(ct)).toStrictEqual(pt);
    });
});