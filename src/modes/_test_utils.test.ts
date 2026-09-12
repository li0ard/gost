import { hexToBytes } from "@noble/hashes/utils.js";
import { Kuznyechik } from "../kuznyechik";
import { Magma, magmaSboxes } from "../magma";

export const KEY_KUZNYECHIK = hexToBytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
export const KEY_MAGMA = hexToBytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
export const KEY_MAGMA2 = hexToBytes("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd");

export const IV_KUZNYECHIK = hexToBytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819");
export const IV_MAGMA = hexToBytes("1234567890abcdef234567890abcdef1");

export const PT_KUZNYECHIK = hexToBytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
export const PT_MAGMA = hexToBytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");

export const _kuznyechik = new Kuznyechik(KEY_KUZNYECHIK);
export const _magma = new Magma(KEY_MAGMA);
export const _magma2 = new Magma(KEY_MAGMA2, magmaSboxes.ID_GOST_28147_89_TEST_PARAM_SET, true);
export const _magma_acpkm = new Magma(KEY_KUZNYECHIK);