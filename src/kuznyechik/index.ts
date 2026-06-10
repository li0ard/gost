import { copyBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { ITER, L, PI, PI_REV } from "./const.js";
import { xorBytes } from "../utils.js";
import type { Cipher } from "../types.js";
import { gfMultiply_lookup as gfMultiply } from "./gf.js";

const S = (input: TArg<Uint8Array>, pi = PI): TRet<Uint8Array> => new Uint8Array([
    pi[input[0]], pi[input[1]], pi[input[2]], pi[input[3]],
    pi[input[4]], pi[input[5]], pi[input[6]], pi[input[7]],
    pi[input[8]], pi[input[9]], pi[input[10]], pi[input[11]],
    pi[input[12]], pi[input[13]], pi[input[14]], pi[input[15]]
]);

const R = (input: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    gfMultiply(input[15], L[0]) ^ gfMultiply(input[0], L[1]) ^
    gfMultiply(input[1], L[2]) ^ gfMultiply(input[2], L[3]) ^
    gfMultiply(input[3], L[4]) ^ gfMultiply(input[4], L[5]) ^
    gfMultiply(input[5], L[6]) ^ gfMultiply(input[6], L[7]) ^
    gfMultiply(input[7], L[8]) ^ gfMultiply(input[8], L[9]) ^
    gfMultiply(input[9], L[10]) ^ gfMultiply(input[10], L[11]) ^
    gfMultiply(input[11], L[12]) ^ gfMultiply(input[12], L[13]) ^
    gfMultiply(input[13], L[14]) ^ gfMultiply(input[14], L[15]),
    ...input.subarray(0, 15)
]);

const Rr = (input: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    ...input.subarray(1, 16),
    gfMultiply(input[0], L[0]) ^ gfMultiply(input[1], L[1]) ^
    gfMultiply(input[2], L[2]) ^ gfMultiply(input[3], L[3]) ^
    gfMultiply(input[4], L[4]) ^ gfMultiply(input[5], L[5]) ^
    gfMultiply(input[6], L[6]) ^ gfMultiply(input[7], L[7]) ^
    gfMultiply(input[8], L[8]) ^ gfMultiply(input[9], L[9]) ^
    gfMultiply(input[10], L[10]) ^ gfMultiply(input[11], L[11]) ^
    gfMultiply(input[12], L[12]) ^ gfMultiply(input[13], L[13]) ^
    gfMultiply(input[14], L[14]) ^ gfMultiply(input[15], L[15])
]);

// Call `R` 16x times
const LL = (input: TArg<Uint8Array>): TRet<Uint8Array> => R(R(R(R(
    R(R(R(R(
        R(R(R(R(
            R(R(R(R(input))))
        ))))
    ))))
))));

// Call `Rr` 16x times
const LLr = (input: TArg<Uint8Array>): TRet<Uint8Array> => Rr(Rr(Rr(Rr(
    Rr(Rr(Rr(Rr(
        Rr(Rr(Rr(Rr(
            Rr(Rr(Rr(Rr(input))))
        ))))
    ))))
))));

const LLS = (block: TArg<Uint8Array>): TRet<Uint8Array> => LL(S(block));
const SLLr = (block: TArg<Uint8Array>): TRet<Uint8Array> => S(LLr(block), PI_REV);

const F = (
    inKey: TArg<Uint8Array>,
    inKey2: TArg<Uint8Array>,
    iter: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(LLS(xorBytes(inKey, iter)), inKey2);

/** Kuznyechik (GOST R 34.12-2015) cipher */
export class Kuznyechik implements Cipher {
    public readonly keySize = 32;
    public readonly blockSize = 16;

    private roundKeys: Uint8Array[];
    /** Kuznyechik (GOST R 34.12-2015) cipher */
    constructor(key: TArg<Uint8Array>) {
        if (key.length !== this.keySize) throw new Error("Invalid key length");

        const roundKeys = Array<Uint8Array>(10);
        roundKeys[0] = key.slice(0, this.blockSize);
        roundKeys[1] = key.slice(this.blockSize);

        let temp1 = copyBytes(roundKeys[0]),
            temp2 = copyBytes(roundKeys[1]),
            temp3 = new Uint8Array(16),
            temp4 = new Uint8Array(16);
        for (let i = 0; i < 4; i++) {
            const baseIndex = i * 8;
        
            temp3 = F(temp1, temp2, ITER[baseIndex]);
            temp4 = copyBytes(temp1);
        
            temp1 = F(temp3, temp4, ITER[baseIndex + 1]);
            temp2 = copyBytes(temp3);
        
            temp3 = F(temp1, temp2, ITER[baseIndex + 2]);
            temp4 = copyBytes(temp1);
        
            temp1 = F(temp3, temp4, ITER[baseIndex + 3]);
            temp2 = copyBytes(temp3);
        
            temp3 = F(temp1, temp2, ITER[baseIndex + 4]);
            temp4 = copyBytes(temp1);
        
            temp1 = F(temp3, temp4, ITER[baseIndex + 5]);
            temp2 = copyBytes(temp3);
        
            temp3 = F(temp1, temp2, ITER[baseIndex + 6]);
            temp4 = copyBytes(temp1);
        
            temp1 = F(temp3, temp4, ITER[baseIndex + 7]);
            temp2 = copyBytes(temp3);
        
            roundKeys[2 + 2 * i] = copyBytes(temp1);
            roundKeys[3 + 2 * i] = copyBytes(temp2);
        }

        this.roundKeys = roundKeys;
    }

    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        if (plaintext.length !== this.blockSize)
            throw new Error("Invalid block size");
        //let currentBlock = copyBytes(plaintext);
        //for (let i = 0; i < 9; i++) currentBlock = LLS(xorBytes(this.roundKeys[i], currentBlock));
        let currentBlock = LLS(xorBytes(this.roundKeys[0], plaintext));
        currentBlock = LLS(xorBytes(this.roundKeys[1], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[2], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[3], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[4], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[5], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[6], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[7], currentBlock));
        currentBlock = LLS(xorBytes(this.roundKeys[8], currentBlock));

        return xorBytes(this.roundKeys[9], currentBlock);
    }

    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        if (ciphertext.length !== this.blockSize)
            throw new Error("Invalid block size");
        let currentBlock = xorBytes(this.roundKeys[9], ciphertext);

        //const reversedKeys = this.roundKeys.slice(0, 9).reverse();
        //for (let i = 0; i < 9; i++) currentBlock = xorBytes(reversedKeys[i], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[8], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[7], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[6], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[5], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[4], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[3], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[2], SLLr(currentBlock));
        currentBlock = xorBytes(this.roundKeys[1], SLLr(currentBlock));

        return xorBytes(this.roundKeys[0], SLLr(currentBlock));
    }
}