// Kuznyechik (GOST R 34.12-2015) and Streebog (GOST R 34.11-2012) S-Box generator ported to TS
// Source: https://who.paris.inria.fr/Leo.Perrin/short-implem.html

const s = new Uint8Array([1, 221, 146, 79, 147, 153, 11, 68, 214, 215, 78, 220, 152, 10, 69]);
const k = new Uint8Array([0, 32, 50, 6, 20, 4, 22, 34, 48, 16, 2, 54, 36, 52, 38, 18, 0]);

export const p = (x: number): number => {
    x &= 0xFF;

    if (x != 0) {
        let l = 1, a = 2;
        while (a !== x) {
            a = ((a << 1) ^ ((a >>> 7) * 29)) & 0xFF;
            l++;
        }

        const mod = l % 17;
        const div = (l / 17) | 0;
        if (mod != 0) return 0xfc ^ k[mod] ^ s[div];
        else return 0xfc ^ k[div];
    } else return 0xfc;
}

/*// Validation
import { PI } from "../src/kuznyechik/const";
for(let i = 0; i < PI.length; i++)
    if(PI[i] != p(i)) throw new Error(`Invalid byte! p(${i})=${p(i)} (exp. ${PI[i]})`);*/