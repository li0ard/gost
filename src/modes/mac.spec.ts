import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { Magma, magmaSboxes } from "../magma";
import { mac, mac_legacy, omac_acpkm } from "./mac";
import { _kuznyechik, _magma, _magma_acpkm, PT_KUZNYECHIK, PT_MAGMA } from "./_test_utils.test";

describe("[MAC] Kuznyechik", () => {
    test("#1", () => {
        const ct = hexToBytes("336f4d296059fbe34ddeb35b37749c67");
        const mode = mac(_kuznyechik);

        expect(mode.compute(PT_KUZNYECHIK)).toStrictEqual(ct)
    });
});

describe("[MAC] Magma", () => {
    test("#1", () => {
        const ct = hexToBytes("154e72102030c5bb");
        const mode = mac(_magma);

        expect(mode.compute(PT_MAGMA)).toStrictEqual(ct)
    });
});

describe("[MAG LEGACY] Magma", () => {
    const key = hexToBytes("54686973206973206d657373616765ff206c656e677468003332206279746573");
    const cipher = new Magma(key, magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET, true);
    
    const pt = hexToBytes("616263");
    test("#1", () => {
        const ct = hexToBytes("b6ff8873ca1a407f");
        const mode = mac_legacy(cipher, hexToBytes("6161616161616161"));
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#2", () => {
        const ct = hexToBytes("28661e40805b1ff9");
        const mode = mac_legacy(cipher);
        
        expect(mode.compute(pt)).toStrictEqual(ct);
    });

    test("#3", () => {
        const ct = hexToBytes("bd5d3b5b2b7b57af");
        const mode = mac_legacy(cipher);
        
        expect(mode.compute(pt.subarray(0,1))).toStrictEqual(ct);
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

const pt_acpkm = hexToBytes("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A001133445566778899AABBCCEEFF0A001122");
describe("[OMAC-ACPKM] Kuznyechik", () => {
    const mode = omac_acpkm(_kuznyechik);

    test("#1", () => {
        const ct = hexToBytes("B5367F47B62B995EEB2A648C5843145E");
        expect(mode.compute(pt_acpkm.subarray(0, 24))).toStrictEqual(ct);
    });

    test("#2", () => {
        const ct = hexToBytes("FBB8DCEE45BEA67C35F58C5700898E5D");
        expect(mode.compute(pt_acpkm)).toStrictEqual(ct);
    });
});

describe("[OMAC-ACPKM] Magma", () => {
    const mode = omac_acpkm(_magma_acpkm);

    test("#1", () => {
        const ct = hexToBytes("A0540E3730ACBCF3");
        expect(mode.compute(pt_acpkm.subarray(0,12))).toStrictEqual(ct);
    });

    test("#2", () => {
        const ct = hexToBytes("34008DAD5496BB8E");
        expect(mode.compute(pt_acpkm.subarray(0,40))).toStrictEqual(ct);
    });
});