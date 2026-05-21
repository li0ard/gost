import { copyBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { ITER, L, PI, PI_REV } from "./const.js";
import { xorBytes } from "../utils.js";
import type { Cipher } from "../types.js";

const BLOCKSIZE = 16, KEYSIZE = 32;

const S = (input: TArg<Uint8Array>, pi = PI): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE);
    //for(let i = 0; i < BLOCKSIZE; i++) result[i] = pi[input[i]];
    result[0] = pi[input[0]];
    result[1] = pi[input[1]];
    result[2] = pi[input[2]];
    result[3] = pi[input[3]];
    result[4] = pi[input[4]];
    result[5] = pi[input[5]];
    result[6] = pi[input[6]];
    result[7] = pi[input[7]];
    result[8] = pi[input[8]];
    result[9] = pi[input[9]];
    result[10] = pi[input[10]];
    result[11] = pi[input[11]];
    result[12] = pi[input[12]];
    result[13] = pi[input[13]];
    result[14] = pi[input[14]];
    result[15] = pi[input[15]];
    
    return result;
}

const gfMultiply = (a: number, b: number): number => {
    let result = 0;
    let high_bit: number;
        
    for(let i = 0; i < 8; i++) {
        if((b & 0b00000001) === 0b00000001) result ^= a;
        high_bit = a & 0b10000000;
        a <<= 1;
        if(high_bit == 0b10000000) a ^= 0b11000011;
        b >>= 1;
    }

    return result & 0xFF;
}

const R = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE);
    result.set(input.slice(0, 15), 1);
    result[0] = input[15];

    //let temp = 0;
    //for (let i = 0; i < BLOCKSIZE; i++) temp ^= gfMultiply(result[i], L[i]);
    let temp = gfMultiply(result[0], L[0]);
    temp ^= gfMultiply(result[1], L[1]);
    temp ^= gfMultiply(result[2], L[2]);
    temp ^= gfMultiply(result[3], L[3]);
    temp ^= gfMultiply(result[4], L[4]);
    temp ^= gfMultiply(result[5], L[5]);
    temp ^= gfMultiply(result[6], L[6]);
    temp ^= gfMultiply(result[7], L[7]);
    temp ^= gfMultiply(result[8], L[8]);
    temp ^= gfMultiply(result[9], L[9]);
    temp ^= gfMultiply(result[10], L[10]);
    temp ^= gfMultiply(result[11], L[11]);
    temp ^= gfMultiply(result[12], L[12]);
    temp ^= gfMultiply(result[13], L[13]);
    temp ^= gfMultiply(result[14], L[14]);
    temp ^= gfMultiply(result[15], L[15]);

    result[0] = temp;

    return result;
}

const Rr = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(BLOCKSIZE);
    //let temp = 0;
    //for (let i = 0; i < BLOCKSIZE; i++) temp ^= gfMultiply(input[i], L[i]);
    let temp = gfMultiply(input[0], L[0]);
    temp ^= gfMultiply(input[1], L[1]);
    temp ^= gfMultiply(input[2], L[2]);
    temp ^= gfMultiply(input[3], L[3]);
    temp ^= gfMultiply(input[4], L[4]);
    temp ^= gfMultiply(input[5], L[5]);
    temp ^= gfMultiply(input[6], L[6]);
    temp ^= gfMultiply(input[7], L[7]);
    temp ^= gfMultiply(input[8], L[8]);
    temp ^= gfMultiply(input[9], L[9]);
    temp ^= gfMultiply(input[10], L[10]);
    temp ^= gfMultiply(input[11], L[11]);
    temp ^= gfMultiply(input[12], L[12]);
    temp ^= gfMultiply(input[13], L[13]);
    temp ^= gfMultiply(input[14], L[14]);
    temp ^= gfMultiply(input[15], L[15]);

    result.set(input.slice(1));
    result[15] = temp;

    return result;
}

const LL = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    //let result = copyBytes(input);
    //for(let i = 0; i < BLOCKSIZE; i++) result = R(result);
    let result = R(copyBytes(input));
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);
    result = R(result);

    return result;
}

const LLr = (input: TArg<Uint8Array>): TRet<Uint8Array> => {
    //let result = copyBytes(input);
    //for(let i = 0; i < BLOCKSIZE; i++) result = Rr(result);
    let result = Rr(copyBytes(input));
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);
    result = Rr(result);

    return result;
}

const LLS = (block: TArg<Uint8Array>): TRet<Uint8Array> => LL(S(block));
const SLLr = (block: TArg<Uint8Array>): TRet<Uint8Array> => S(LLr(block), PI_REV);

const F = (
    in_key1: TArg<Uint8Array>,
    in_key2: TArg<Uint8Array>,
    iter_constant: TArg<Uint8Array>
): TRet<Uint8Array> => xorBytes(LLS(xorBytes(in_key1, iter_constant)), in_key2);

/** Kuznyechik (GOST R 34.12-2015) cipher */
export class Kuznyechik implements Cipher {
    public readonly keySize = KEYSIZE;
    public readonly blockSize = BLOCKSIZE;

    private roundKeys: Uint8Array[];
    /** Kuznyechik (GOST R 34.12-2015) cipher */
    constructor(key: TArg<Uint8Array>) {
        if (key.length !== this.keySize) throw new Error("Invalid key length");

        const roundKeys: Uint8Array[] = Array(10).fill(null).map(() => new Uint8Array(this.blockSize));
        roundKeys[0] = key.slice(0, this.blockSize);
        roundKeys[1] = key.slice(this.blockSize);

        let temp1: Uint8Array = copyBytes(roundKeys[0]);
        let temp2: Uint8Array = copyBytes(roundKeys[1]);
        let temp3: Uint8Array = new Uint8Array(16);
        let temp4: Uint8Array = new Uint8Array(16);

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

        currentBlock = xorBytes(this.roundKeys[9], currentBlock);
        return currentBlock;
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
        currentBlock = xorBytes(this.roundKeys[0], SLLr(currentBlock));

        return currentBlock;
    }
}