import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Kuznyechik } from "../kuznyechik";
import { Magma, magmaSboxes } from "../magma";
import { mac, mac_legacy, omac_acpkm } from "./mac";

describe("[MAC] Kuznyechik", () => {
    test("#1", () => {
        const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        const pt = hexToBytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
        const ct = hexToBytes("336f4d296059fbe34ddeb35b37749c67");
        const cipher = new Kuznyechik(key);
        const mode = mac(cipher)

        expect(mode.compute(pt)).toStrictEqual(ct)
    });
});

describe("[MAC] Magma", () => {
    test("#1", () => {
        const key = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const pt = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        const ct = hexToBytes("154e72102030c5bb");
        const cipher = new Magma(key);
        const mode = mac(cipher)

        expect(mode.compute(pt)).toStrictEqual(ct)
    });
});

describe("[MAG LEGACY] Magma", () => {
    const key = hexToBytes("54686973206973206d657373616765ff206c656e677468003332206279746573");
    const cipher = new Magma(key, magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET, true);
    
    test("#1", () => {
        const pt = hexToBytes("616263");
        const ct = hexToBytes("b6ff8873ca1a407f");
        const mode = mac_legacy(cipher, hexToBytes("6161616161616161"));
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#2", () => {
        const pt = hexToBytes("616263");
        const ct = hexToBytes("28661e40805b1ff9");
        const mode = mac_legacy(cipher);
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#3", () => {
        const pt = hexToBytes("61");
        const ct = hexToBytes("bd5d3b5b2b7b57af");
        const mode = mac_legacy(cipher);
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#4", () => {
        const pt = new Uint8Array(13).fill(0x78);
        const ct = hexToBytes("917ee1f1a668fbd3");
        const mode = mac_legacy(cipher);
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#5", () => {
        const pt = new Uint8Array(128).fill(0x55);
        const ct = hexToBytes("1a06d1bad74580ef");
        const mode = mac_legacy(cipher);
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });
});

describe("[OMAC-ACPKM] Kuznyechik", () => {
    const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    const cipher = new Kuznyechik(key);
    const mode = omac_acpkm(cipher);

    test("#1", () => {
        const pt = hexToBytes("1122334455667700FFEEDDCCBBAA99880011223344556677");
        const ct = hexToBytes("B5367F47B62B995EEB2A648C5843145E");

        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#2", () => {
        const pt = hexToBytes("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A001133445566778899AABBCCEEFF0A001122");
        const ct = hexToBytes("FBB8DCEE45BEA67C35F58C5700898E5D");

        expect(mode.compute(pt)).toStrictEqual(ct);
    });
});

describe("[OMAC-ACPKM] Magma", () => {
    const key = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    const cipher = new Magma(key);
    const mode = omac_acpkm(cipher);

    test("#1", () => {
        const pt = hexToBytes("1122334455667700FFEEDDCC");
        const ct = hexToBytes("A0540E3730ACBCF3");
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#2", () => {
        const pt = hexToBytes("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A1122334455667788");
        const ct = hexToBytes("34008DAD5496BB8E");

        expect(mode.compute(pt)).toStrictEqual(ct);
    });
});