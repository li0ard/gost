import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { describe, test, expect } from "bun:test";
import { streebog256, streebog512 } from ".";

const performTest = (
    input: Uint8Array,
    expected256: Uint8Array,
    expected512: Uint8Array
) => {
    expect(streebog256(input)).toStrictEqual(expected256 as TRet<Uint8Array>);
    expect(streebog512(input)).toStrictEqual(expected512 as TRet<Uint8Array>);
}

describe("[HASH] Streebog (GOST R 34.11-2012)", () => {
    test("#1", () => performTest(
        new TextEncoder().encode("210987654321098765432109876543210987654321098765432109876543210").reverse(),
        hexToBytes("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d").reverse(),
        hexToBytes("486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b").reverse()
    ));

    test("#2", () => performTest(
        hexToBytes("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1").reverse(),
        hexToBytes("508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d").reverse(),
        hexToBytes("28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e").reverse()
    ));

    test("#3", () => performTest(
        hexToBytes("d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000002400000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hexToBytes("c766085540caaa8953bfcf7a1ba220619cee50d65dc242f82f23ba4b180b18e0"),
        hexToBytes("3d46a117a91ac9220f6dee4d1db83f0d018f799b58ca118648f7d6e4f82e37e951459776e866d4e31467afc843ce88e8d6db62e3fb93cb9fcd60703de7492828")
    ));
});