import { hexToBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { describe, test, expect } from "bun:test";
import { gost2001CC, gost2001Test, gost256A, gost256B, gost256C, gost256D, gost512A, gost512B, gost512C, gost512Test } from "./index.js";
import type { Signer } from "../types.js";

const performTest = (
    signer: Signer,
    privKey: TArg<Uint8Array>,
    digest: TArg<Uint8Array>,
    rand: TArg<Uint8Array>,
    expectedPk: TArg<Uint8Array>,
    expectedSign: TArg<Uint8Array>
) => {
    const publicKey = signer.getPublicKey(privKey, false);
    const signature = signer.sign(privKey, digest, rand);
    expect(publicKey).toStrictEqual(expectedPk as TRet<Uint8Array>);
    expect(signature).toStrictEqual(expectedSign as TRet<Uint8Array>);
    expect(signer.verify(publicKey, digest, expectedSign)).toBeTrue();
    // Generate and verify deterministic signature
    expect(signer.verify(
        publicKey,
        digest,
        signer.sign(privKey, digest)
    )).toBeTrue();
}

describe("[SIGN] GOST R 34.10-2001", () => {
    const digest = hexToBytes("2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5");
    const rand = hexToBytes("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");
    test("ID_GOSTR3410_2001_PARAM_SET_CC", () => {
        const privKey = hexToBytes("18c2e480f2e85a3c4b26f202f9610c744a584ba087e254e55c47faba6888f237");
        const expectedPk = hexToBytes("041e0ccfac352bf57fd18808092406e72487ae138776170379a7bebb61e5b14535094129e0f59e2fc37345a0869a0694a5cacc4fcb272b1763e4344a090d93f874");
        const expectedSign = hexToBytes("1ba4446a12e1a878d675352dcfd4580c9ae7919dc6428b39966b7354a9d576962722e6f531f3bf76bb27c90f3ab0fb6b11d0a2810ac2f18e22ebbb9f6d5fbfcb");

        performTest(gost2001CC, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2001_TEST_PARAM_SET", () => {
        const privKey = hexToBytes("7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28");
        const expectedPk = hexToBytes("047f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da");
        const expectedSign = hexToBytes("41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc049301456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40");
        performTest(gost2001Test, privKey, digest, rand, expectedPk, expectedSign);
    });
});

describe("[SIGN] GOST R 34.10-2012 256 bit", () => {
    const digest = hexToBytes("2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5");
    const rand = hexToBytes("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");

    test("ID_GOSTR3410_2012_256_PARAM_SET_A", () => {
        const privKey = hexToBytes("0ca68a44333dbee1daea1e80dbdd560a43215886a392472b898ed3721e1177e0");
        const expectedPk = hexToBytes("04783f55db27faa3703997d29623c88394068c88065e4df424a53f586fa6c8aa7712a7f3b653a2ba53a8cbc7c039223138677c8ef78ec57163a38c617c4f4eb383");
        const expectedSign = hexToBytes("01b69df1e54b083516a398ee54f6975b213c384b39020bfa983766b7a458a23e1f4be89d22c83e676cbac9154efcbad3274eb5ed6655fa9d040d18d15f21dc60");
        performTest(gost256A, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2012_256_PARAM_SET_B", () => {
        const privKey = hexToBytes("02433a376ac33a077173cc52df6947b0cc7f9442c274308992ea884ba583ff81");
        const expectedPk = hexToBytes("045cae92068a723bbca9a0b37d234689ae4687e5e24857828c77aa887a47e5d88f8aab3103ba0ca8edb5e9ec5b66cc921cad91a4899041359c4ee2cd8a34414fde");
        const expectedSign = hexToBytes("74e939c637a79a5b7e39dc15976befb324acdb74e2fa8d434aba0da9ebf8de8fd021c91aa35ad922e4d42c764e5b27f4dcfc2ad9e08718232cb32d55971aba76");
        performTest(gost256B, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2012_256_PARAM_SET_C", () => {
        const privKey = hexToBytes("487bb4201b74cdd8e4f7f0e35cbb4c944409b394e2f5c8556c6af770af38640b");
        const expectedPk = hexToBytes("045931d38dcb2d8d4b7947e423ab4d03713706c33fb7d499d15d7ea07e0efb5db6020d69bbf58bb30444b4607735912b64dd15789f6680b8f6bb5dc35277a8e6bd");
        const expectedSign = hexToBytes("17ed3090d60d6335be4f660c2456481ad92da7a0abe110b31e9f29eb68b260c529d68ee453fb1799b9bcaf0d5c24c27c6bf8bfe9b243de54a9a33a2429ed4df5");
        performTest(gost256C, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2012_256_PARAM_SET_D", () => {
        const privKey = hexToBytes("84c2091682a36ff192359e41e72848cdeca428f1f458561e4c6b1015b8c6e5af");
        const expectedPk = hexToBytes("0459ab55cb96e15ed37bc5a997c1347d11ef401d769e0dc1d0a4c0745f3262aa51654d32cc2c3c6871c632f7f741ac62bd51c542c2467af81f66e5a1b21aa560a1");
        const expectedSign = hexToBytes("6ffa317b4f37c95226f509e1f53bfa3ff18559e8d5c4a81e681316da5cbe271e2a859a2c463f3116a9b861d09767225fc0353ecb4124c83d12c987593e444930");
        performTest(gost256D, privKey, digest, rand, expectedPk, expectedSign);
    });
});

describe("[SIGN] GOST R 34.10-2012 512 bit", () => {
    const digest = hexToBytes("3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C");
    const rand = hexToBytes("0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1");

    test("ID_GOSTR3410_2012_512_TEST_PARAM_SET", () => {
        const privKey = hexToBytes("0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4")
        const expectedPk = hexToBytes("04115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe137c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec");
        const expectedSign = hexToBytes("2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae361081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a");
        performTest(gost512Test, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2012_512_PARAM_SET_A", () => {
        const privKey = hexToBytes("480f669784fd01b5cb7b5f919159af5b9a78c332ec07ca2602de83529e061b4988ac5b38345206df49894c6a4428825acf2f6ff1ecb5e578584e654f9dfd7192");
        const expectedPk = hexToBytes("04e25d47f1cc5391e872213ef0a55c90ef21cef5c28f1c075f7a15e741791e12903e62ea39e0075b83b4346678c63d5451be6f53a1e7507f7d1cc6a3ea6a0d69ad14f216dbc88698a8f0267d6fc8f46b59ead371a7c5a87774b0c0f071f456e48ff32ec0f8cdc93432e528e50925bd571546e431aa3cfef1f2efa57ca5f9bb0865");
        const expectedSign = hexToBytes("561b01afb058d86534a5bbbe50ec01b620bc4379318d7bf6f6c9248696920c68a2fab805f89d252138577516a866df301abf7be0329a6eb64765f564db8dc11c062952d8f0ff0597be2185f67d423af24aca3361b6bfc149fe1f81f698c49e52632b44349164a0ea52420646bacf5b91acead74a6a30dc6588f4a137e9e53f7a");
        performTest(gost512A, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2012_512_PARAM_SET_B", () => {
        const privKey = hexToBytes("4a2a20eb3ad1371ce57a59d610f5ebfac41a59556116528d6fe2347a64c2129fa2f3f75ce30ea7853bb332720e55faab782f3274339e950286eef435c044ad47");
        const expectedPk = hexToBytes("0448aa39dd73b402a50886e53445135cff6bde60368c6c04e8965324ec9bfbcaf1414f0b532584f415c67cef8b368652d0ba71678a317fc8710fad8cf916e5724f4795de5d0031c6ac4de6ab0421868fdf8e8fd141347144c8130ce614ce724448cecb11bcdf7e40b048f07b8dfaa2b6a68cf6178908340def6dc77d62ec191a74");
        const expectedSign = hexToBytes("6c4bb1b593c2726e929b18ca3cc83c2487366a3976a74a4b6903de7fdbf234097e6edc873e9b8652b7b7864654e25af53646542b3030c21dac985a66831decb926c5f76e316b3977bf31c3fc3685d0131062483641927a64be3f2cf117e44cfb6353efbf62b1c373d272018016edb03ecc5deda627f79a24760463c0aedcaed8");
        performTest(gost512B, privKey, digest, rand, expectedPk, expectedSign);
    });

    test("ID_GOSTR3410_2012_512_PARAM_SET_C", () => {
        const privKey = hexToBytes("3837dc2b6431eb10076f37b2e480abbe81239b820b6ab0634e2c87e3b59e50fbf86575221e2947d006049831ac8f162cbef01ba56df5ba12df1f40a19b956f39");
        const expectedPk = hexToBytes("04a0137475566bf98ca554aebff738eb618a5da2da176743e19a1500fec8baaa35ead67cc5f996d3964d8e9313043451e03847292ebff061dcaa86efa0be7290f151a0bac67eabf750a8078de9ca7641f993363b63e013ef632760bcd467115c6e689dc5d13ecb8e353878da7adf4cad0718578b19f0fdf1fae823a7d376189f4c");
        const expectedSign = hexToBytes("0e4d15b0222c49cde4c7e63375f42fd0e9895644357ee2fd43f4743b9a22a76f95e3c9e296674942a56573648085b65117471fdc23c61fe730bafeb1130326210a9deda97067eaf32bc3986368a1a2c5016b0a75c55f2fe64798810e2490232ae40d2643fd6634defb39f353b8572865376196e4ea0ff38065b588577ccb4a4d");
        performTest(gost512C, privKey, digest, rand, expectedPk, expectedSign);
    });
});