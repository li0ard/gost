// Generating round constants for Streebog (GOST R 34.11-2012)
// Source: https://tc26.ru/upload/medialibrary/efb/streebog_constants_eng%20Rudskoi.pdf

import { hexToBytes, bytesToHex, type TArg, type TRet } from "@noble/hashes/utils.js";
import { PI } from "../src/kuznyechik/const.js";
import { pad1, xorBytes } from "../src/utils.js";
import { numberToBytesBE } from "@noble/curves/utils.js";

const BLOCKSIZE = 64;
const _0020 = new Uint8Array([0, 0, 2, 0]);
const _0 = new Uint8Array(64);

const add512 = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const c = new Uint8Array(64);
    const tmpA = new Uint8Array(64);
    const tmpB = new Uint8Array(64);

    for (let i = 0; i < a.length; i++) tmpA[63 - i] = a[a.length - i - 1];
    for (let i = 0; i < b.length; i++) tmpB[63 - i] = b[b.length - i - 1];
    for (let i = 63, tmp = 0; i >= 0; i--) {
        tmp = tmpA[i] + tmpB[i] + (tmp >> 8);
        c[i] = tmp & 0xff;
    }

    return c;
}

const S = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE);
    for(let i = 0; i < BLOCKSIZE; i++) result[i] = PI[input[i]];

    return result;
}

const P = (input: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    input[0], input[8], input[16], input[24], input[32], input[40], input[48], input[56],
    input[1], input[9], input[17], input[25], input[33], input[41], input[49], input[57],
    input[2], input[10], input[18], input[26], input[34], input[42], input[50], input[58],
    input[3], input[11], input[19], input[27], input[35], input[43], input[51], input[59], 
    input[4], input[12], input[20], input[28], input[36], input[44], input[52], input[60],
    input[5], input[13], input[21], input[29], input[37], input[45], input[53], input[61],
    input[6], input[14], input[22], input[30], input[38], input[46], input[54], input[62],
    input[7], input[15], input[23], input[31], input[39], input[47], input[55], input[63]
]);

// Modificated MDS-matrix
const A_init = new Uint32Array([
    0x0e2d05d4, 0xe55f0471, 0x1c5a0ad9, 0xbbbe08e2, 0x38b414c3, 0x070d10b5, 0x701928f7, 0x0e1a201b,
    0xe032509f, 0x1c344036, 0xb164a04f, 0x3868806c, 0x13c8319e, 0x70d071d8, 0x26e1624d, 0xe0d1e2c1,
    0x02f17181, 0x01cb8805, 0x0493e273, 0x02e7610a, 0x0857b5e6, 0x04bfc214, 0x10ae1bbd, 0x080ff528,
    0x202d360b, 0x101e9b50, 0x405a6c16, 0x203c47a0, 0x80b4d82c, 0x40788e31, 0x7119c158, 0x80f06d62,
    0xf6e75e1c, 0x54ad5b09, 0x9dbfbc38, 0xa82bb612, 0x4b0f0970, 0x21561d24, 0x961e12e0, 0x42ac3a48,
    0x5d3c24b1, 0x84297490, 0xba784813, 0x7952e851, 0x05f09026, 0xf2a4a1a2, 0x0a91514c, 0x95393335,
    0x8a2866fa, 0xba0fb2b9, 0x6550cc85, 0x051e1503, 0xcaa0e97b, 0x0a3c2a06, 0xe531a3f6, 0x1478540c,
    0xbb62379d, 0x28f0a818, 0x07c46e4b, 0x50912130, 0x0ef9dc96, 0xa0534260, 0x1c83c95d, 0x31a684c0,
    0x15551739, 0x0fbae461, 0x2aaa2e72, 0x1e05b9c2, 0x54255ce4, 0x3c0a03f5, 0xa84ab8b9, 0x7814069b,
    0x21940103, 0xf0280c47, 0x42590206, 0x9150188e, 0x84b2040c, 0x53a0306d, 0x79150818, 0xa63160da,
    0x9da01c5e, 0x112c36a2, 0x4b3138bc, 0x22586c35, 0x96627009, 0x44b0d86a, 0x5dc4e012, 0x8811c1d4,
    0xbaf9b124, 0x6122f3d9, 0x05831348, 0xc24497c3, 0x0a772690, 0xf5885ff7, 0x14ee4c51, 0x9b61be9f,
    0x394cd015, 0x2a045f27, 0x7298d12a, 0x5408be4e, 0xe441d354, 0xa8100d9c, 0xb982d7a8, 0x21201a49,
    0x0375df21, 0x42403492, 0x06eacf42, 0x84806855, 0x0ca5ef84, 0x7971d0aa, 0x183baf79, 0xf2e2d125,
    0x719a0224, 0x76a5650e, 0xe2450448, 0xec3bca1c, 0xb58a0890, 0xa976e538, 0x1b651051, 0x23ecbb70,
    0x36ca20a2, 0x46a907e0, 0x6ce54035, 0x8c230eb1, 0xd8bb806a, 0x69461c13, 0xc10771d4, 0xd28c3826
]);

const L = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE);

    for (let i = 0; i < 8; i++) {
        const parts = new Uint32Array(2);
        const tmp = input.slice(i * 8, i * 8 + 8).reverse();

        for (let j = 0; j < 8; j++) {
            for (let k = 0; k < 8; k++) {
                if (((tmp[7 - j] >> (7 - k)) & 1) === 1) {
                    const row = j * 8 + k;
                    parts[0] ^= A_init[row * 2];
                    parts[1] ^= A_init[row * 2 + 1];
                }
            }
        }

        result.set(numberToBytesBE(parts[0], 4), i * 8);
        result.set(numberToBytesBE(parts[1], 4), i * 8 + 4);
    }

    return result;
}

const LPS = (input: TArg<Uint8Array>): TRet<Uint8Array> => L(P(S(input)));

const E = (block: TArg<Uint8Array>, keys: TArg<Uint8Array>): TRet<Uint8Array> => {
    let c = xorBytes(block, keys);
    for (let i = 0; i < 12; i++) {
        // Removed `C` constants
        block = LPS(block);
        c = xorBytes(LPS(c), block);
    }

    return c;
}

const G = (
    hash: TArg<Uint8Array>,
    n: TArg<Uint8Array>,
    message: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(xorBytes(E(LPS(xorBytes(n, hash)), message), n), message);

// Modificated Streebog-like 512 bit hash function (use LE instead of BE)
const streeboglike512 = (buffer: TArg<Uint8Array>): TRet<Uint8Array> => {
    const message = buffer;
    let n = new Uint8Array(64);
    let sigma = new Uint8Array(64);
    let hash = new Uint8Array(64);

    let blocks: number = 1;
    for (let i = message.length; i >= 64; i -= 64) {
        const pos: number = message.length - blocks * 64;

        hash = G(n, hash, message.subarray(pos, pos + 64));
        n = add512(n, _0020);
        sigma = add512(sigma, message.subarray(pos, pos + 64));
        blocks++;
    }

    let paddedMsg = new Uint8Array(64);
    const msg = message.subarray(0, message.length - (blocks - 1) * 64);
    if (msg.length < 64) {
        paddedMsg = pad1(paddedMsg, 64);

        paddedMsg[64 - msg.length - 1] = 0x01;
        for (let i = 0; i < msg.length; i++) paddedMsg[64 - msg.length + i] = msg[i];
    }


    return G(
        _0,
        G(_0, G(n, hash, paddedMsg), add512(n, numberToBytesBE(msg.length * 8, 4))),
        add512(sigma, paddedMsg)
    );
}

// Names of authors of the standard (in CP-1251)
const C_init = [
    hexToBytes("e2e5ede1e5f0c3"), // Гребнев
    hexToBytes("f7e8e2eef0e8ece8e4e0ebc220e9e5e3f0e5d1"), // Сергей Владимирович
    hexToBytes("f5f3ecc4"), // Дмух
    hexToBytes("f7e8e2eef0e4ede0f1eae5ebc020e9e5f0e4edc0"), // Андрей Александрович
    hexToBytes("ede8e3fbc4"), // Дыгин
    hexToBytes("f7e8e2eeebe9e0f5e8cc20f1e8ede5c4"), // Денис Михайлович
    hexToBytes("ede8f5fef2e0cc"), // Матюхин
    hexToBytes("f7e8e2eef0eef2eae8c220e9e8f0f2e8ecc4"), // Дмитрий Викторович
    hexToBytes("e9eeeaf1e4f3d0"), // Рудской
    hexToBytes("f7e8e2e5f0eee3c820f0e8ece8e4e0ebc2"), // Владимир Игоревич
    hexToBytes("ede8eaf8e8d8"), // Шишкин
    hexToBytes("f7e8e2e5e5f1eae5ebc020e9e8ebe8f1e0c2") // Василий Алексеевич
];

for(let i = 1; i <= 12; i++)
    console.log(`C_${i} = ${bytesToHex(streeboglike512(C_init[i - 1]))}`);