// S-Box (PI) generates by Leo Perrin method
// Source: https://who.paris.inria.fr/Leo.Perrin/short-implem.html

const s = /* @__PURE__ */ Uint8Array.of(1, 221, 146, 79, 147, 153, 11, 68, 214, 215, 78, 220, 152, 10, 69),
    k = /* @__PURE__ */ Uint8Array.of(0, 32, 50, 6, 20, 4, 22, 34, 48, 16, 2, 54, 36, 52, 38, 18, 0);

export const PI = /* @__PURE__ */ (() => {
    const pi = new Uint8Array(256);
    pi[0] = 0xfc;
    for (let l = 1, a = 1; l <= 255; l++) {
        a = ((a << 1) ^ ((a >>> 7) * 29)) & 0xff;
        const mod = l % 17, div = (l / 17) | 0;
        pi[a] = mod
            ? 0xfc ^ k[mod] ^ s[div]
            : 0xfc ^ k[div];
    }

    return pi;
})();

export const L = /* @__PURE__ */ Uint8Array.of(1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148);