import { concatBytes, copyBytes, createHasher, type TArg, type TRet } from "@noble/hashes/utils.js";
import { streebog256hmac } from "./hmac.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { Streebog256, streebog256, streebog512 } from "./streebog/index.js";
import { Gost341194 } from "./gost341194/index.js";
import { pad1, xorBytes } from "./utils.js";

const _0 = new Uint8Array([0]);
const _1 = new Uint8Array([1]);
const _0100 = new Uint8Array([1,0]);
const _36 = new Uint8Array(64).fill(0x36);
const _5C = new Uint8Array(64).fill(0x5C);

export const kdf_gostr3411_2012_256 = (
    key: TArg<Uint8Array>,
    label: TArg<Uint8Array>,
    seed: TArg<Uint8Array>
): TRet<Uint8Array> => streebog256hmac(
    key,
    concatBytes(_1, label, _0, seed, _0100)
);

export const kdf_tree_gostr3411_2012_256 = (
    key: TArg<Uint8Array>,
    label: TArg<Uint8Array>,
    seed: TArg<Uint8Array>,
    keys: number,
    i_len: number = 1
): TRet<Uint8Array>[] => {
    const keymat = [];
    const length = numberToBytesBE(keys * 32 * 8, 2);

    for(let i = 0; i < keys; i++)
        keymat.push(streebog256hmac(key, concatBytes(
            numberToBytesBE(i + 1, i_len),
            label,
            _0,
            seed,
            length
        )));

    return keymat;
}

export const streebog256pbkdf2 = (
    password: TArg<Uint8Array>,
    salt: TArg<Uint8Array>,
    iter: number,
    dkLen: number
): TRet<Uint8Array> => pbkdf2(streebog256, password, salt, { dkLen, c: iter });

export const streebog512pbkdf2 = (
    password: TArg<Uint8Array>,
    salt: TArg<Uint8Array>,
    iter: number,
    dkLen: number
): TRet<Uint8Array> => pbkdf2(streebog512, password, salt, { dkLen, c: iter });

export const gost341194pbkdf2 = (
    password: TArg<Uint8Array>,
    salt: TArg<Uint8Array>,
    iter: number,
    dkLen: number
): TRet<Uint8Array> => pbkdf2(createHasher(Gost341194.create), password, salt, { dkLen, c: iter });

export const cpkdf = (
    password: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const hasher = Streebog256.create();
    const bs = 64;
    if(password.length * 4 > 1024)
        throw new Error("Password cannot be longer than 256 symbols");

    const pin = new Uint8Array(password.length * 4);
    for(let i = 0; i < password.length; i++) pin[i*4] = password[i];

    hasher.update(salt);
    if(password.length != 0) hasher.update(pin);
    const hash = hasher.digest();

    const c = new Uint8Array(64);
    c.set(new TextEncoder().encode("DENEFH028.760246785.IUEFHWUIO.EF"));
    const m0 = new Uint8Array(bs), m1 = new Uint8Array(bs);
    for(let j = 0; j < (password.length != 0 ? 2000 : 2); j++) {
        m0.set(xorBytes(c, _36));
        m1.set(xorBytes(c, _5C));

        hasher.update(m0);
        hasher.update(hash);
        hasher.update(m1);
        hasher.update(hash);

        c.set(pad1(hasher.digest(), bs));
    }

    m0.set(xorBytes(c, _36));
    m1.set(xorBytes(c, _5C));
    hasher.update(m0.subarray(0, 32));
    hasher.update(salt);
    hasher.update(m1.subarray(0, 32));
    if(password.length != 0) hasher.update(pin);

    hasher.update(hasher.digest());

    return hasher.digest();
}