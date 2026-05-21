import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { kexp15, kwp } from "./wrap";
import { Kuznyechik } from "../kuznyechik";
import { Magma } from "../magma";

describe("[KEXP] Kuznyechik", () => {
    const key = hexToBytes("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
    const keyEnc = hexToBytes("202122232425262728292A2B2C2D2E2F38393A3B3C3D3E3F3031323334353637");
    const keyMac = hexToBytes("08090A0B0C0D0E0F0001020304050607101112131415161718191A1B1C1D1E1F");
    const iv = hexToBytes("0909472DD9F26BE8");
    const kexp = hexToBytes("E36184E84E8D736FF36CC2E5AE065DC656B23C20F549B02FDFF88E1F3F30D8C29A53F3CA554DBAD80DE152B9A4625B32");
    const mode = kexp15(new Kuznyechik(keyEnc), new Kuznyechik(keyMac), iv);

    test("#1", () => {
        expect(mode.wrap(key)).toStrictEqual(kexp);
        expect(mode.unwrap(kexp)).toStrictEqual(key);
    });
});

describe("[KEXP] Magma", () => {
    const key = hexToBytes("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
    const keyEnc = hexToBytes("202122232425262728292A2B2C2D2E2F38393A3B3C3D3E3F3031323334353637");
    const keyMac = hexToBytes("08090A0B0C0D0E0F0001020304050607101112131415161718191A1B1C1D1E1F");
    const iv = hexToBytes("67BED654");
    const kexp = hexToBytes("CFD5A12D5B81B6E1E99C916D07900C6AC12703FB3ABDED55567BF3742C899C755DAFE7B42E3A8BD9");
    const mode = kexp15(new Magma(keyEnc), new Magma(keyMac), iv);

    test("#1", () => {
        expect(mode.wrap(key)).toStrictEqual(kexp);
        expect(mode.unwrap(kexp)).toStrictEqual(key);
    });
});

describe("[KWP] Magma", () => {
    const key = hexToBytes("ec44b411637fc66b680e0e721642b99bb1e792ee183cab872254d5850e692ed9");
    const ukm = hexToBytes("882676dc2ccd53e3");
    const mode = kwp(key);
    const mode2 = kwp(key, true);

    const cek256 = hexToBytes("76349ba2907d81428f8f1bc06091a2b5bb424d709bb3d1eb47daaf7f47cd3703");
    const cek512 = hexToBytes("c98f2ca843ac1a77f66ee183221d476cf27242af5dd69091cb4fe9a4576864a07d8181124e0e5812c14e7ee0b8b9dd7ee0142548192403cd0577021508287d2f");

    test("#1 (Standard wrapping, 256)", () => {
        const wrapped = hexToBytes("882676dc2ccd53e36be8cffcf11616cad1ee673b8f364fd7e36a635c4c398d9133832c5694b29defea6196c4");
        
        expect(mode.wrap(ukm, cek256)).toStrictEqual(wrapped);
        expect(mode.unwrap(wrapped)).toStrictEqual(cek256);
    });

    test("#2 (Standard wrapping, 512)", () => {
        const wrapped = hexToBytes("882676dc2ccd53e322a20562bc019feb70b89bb32d9d5149cf1e23c5f7b79241ecad33a787c98dfe3c8b5468526c5ca9d8b2ae2e8f23ec6175b0d3b6b331b2d1aa1ecbde578404facc35efa2");
        
        expect(mode.wrap(ukm, cek512)).toStrictEqual(wrapped);
        expect(mode.unwrap(wrapped)).toStrictEqual(cek512);
    });

    test("#3 (CryptoPro wrapping, 256)", () => {
        const wrapped = hexToBytes("882676dc2ccd53e328ffbdc874b57f5156ea0700335b22c67dc8a8118e60519f7c39b4385a876cac9a7fd524");
        
        expect(mode2.wrap(ukm, cek256)).toStrictEqual(wrapped);
        expect(mode2.unwrap(wrapped)).toStrictEqual(cek256);
    });

    test("#4 (CryptoPro wrapping, 512)", () => {
        const wrapped = hexToBytes("882676dc2ccd53e34dc39e5590113d1d42f902430b34ef1c2c2e070dc859251bc63688f292d1239c5a23a1d46f385c42bd13b9541939cbe711495c73df7052634cc8042279878d9b056ebb16");
        
        expect(mode2.wrap(ukm, cek512)).toStrictEqual(wrapped);
        expect(mode2.unwrap(wrapped)).toStrictEqual(cek512);
    });
});