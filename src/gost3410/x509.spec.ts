import { hexToBytes, type TArg } from "@noble/hashes/utils.js";
import { test, expect } from "bun:test";
import { AsnConvert, AsnProp, AsnPropTypes, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { getCurveByOid, getHashByCurveOid, getHashByOid } from "../oids.js";
import type { ECDSA, SignOpts } from "../types.js";
import { reverseBytes } from "../utils.js";

class PublicKeyParameters {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    curve!: string;

    @AsnProp({ type: AsnPropTypes.ObjectIdentifier, optional: true })
    digest?: string;
}

/**
 * Adapter for PKI practice
 * 
 * Unfortunately, GOST doesn't have unificated serialization
 * 
 * The core follows the standard, real-world PKI encodes values differently:
 * - Secret key, digest: LE
 * - Public key: `X ‖ Y`, each coordinate LE
 * - Signature: `S ‖ R`, each half BE
 */
const toPkiAdapter = (signer: ECDSA) => {
    const { swapHalves, reverseCoords } = signer.utils;

    return Object.freeze({
        getPublicKey: (
            secretKey: TArg<Uint8Array>
        ) => reverseCoords(signer.getPublicKey(reverseBytes(secretKey))),

        sign: (
            secretKey: TArg<Uint8Array>,
            digest: TArg<Uint8Array>,
            opts?: SignOpts
        ) => swapHalves(signer.sign(reverseBytes(secretKey), reverseBytes(digest), opts)),

        verify: (
            publicKey: TArg<Uint8Array>,
            digest: TArg<Uint8Array>,
            signature: TArg<Uint8Array>
        ) => signer.verify(reverseCoords(publicKey), reverseBytes(digest), swapHalves(signature))
    });
}

const proceedCertitificate = (
    certificate: TArg<Uint8Array>,
    privateKey?: TArg<Uint8Array>,
) => {
    const parsed = AsnConvert.parse(certificate, Certificate);
    const parameters = AsnConvert.parse(parsed.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters!, PublicKeyParameters);

    const curve = getCurveByOid(parameters.curve);
    if(!curve) throw new Error("Invalid curve parameters");
    const signer = toPkiAdapter(curve);

    let hasher = undefined;
    if(parameters.digest) hasher = getHashByOid(parameters.digest);
    else hasher = getHashByCurveOid(parameters.curve);
    if(!hasher) throw new Error("Invalid hash function");

    const spk = new Uint8Array(
        AsnConvert.parse(parsed.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, OctetString).buffer
    );

    if(privateKey)
        expect(signer.getPublicKey(privateKey)).toStrictEqual(spk);

    expect(signer.verify(
        spk,
        hasher(new Uint8Array(parsed.tbsCertificateRaw!)),
        new Uint8Array(parsed.signatureValue)
    )).toBeTrue();
}

test("[X.509] GOST R 34.10-2001", () => {
    // RFC 9215. Appendix D. With OID for hash function
    const privateKey = hexToBytes("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28").reverse();
    const certificate = `
MIIBLTCB26ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw
IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4
YW1wbGUwZjAfBggqhQMHAQEBATATBgcqhQMCAiMABggqhQMHAQECAgNDAARAC9hv
5djbiWaPeJtOHbqFhcVQi0XsW1nYkG3bcOJJK3/ad/+HGhD73ydm0pPF0WSvuzx7
lzpByIXRHXDWibTxJqMTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhQMHAQEDAgNB
AE1T8BL+CBd2UH1Nm7gfAO/bTu/Uq4O6xLrPc1Fzz6gcQaoo0vGrFIKAzZ7Vb+2k
GXQFNVSkJ2e4OtBD/TncBJM=`;

    proceedCertitificate(Uint8Array.fromBase64(certificate), privateKey);
});

test("[X.509] GOST R 34.10-2012 256 bit", () => {
    // RFC 9215. Appendix D. Without OID for hash function
    const privateKey = hexToBytes("3A929ADE789BB9BE10ED359DD39A72C10B87C83F80BE18B85C041F4325B62EC1").reverse();
    const certificate = `
MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw
IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4
YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP
7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE
aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ
yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6
DglzGOeubudp`;

    proceedCertitificate(Uint8Array.fromBase64(certificate), privateKey);
});

test("[X.509] GOST R 34.10-2012 512 bit", () => {
    // RFC 9215. Appendix D. Without OID for hash function
    const privateKey = hexToBytes("0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4").reverse();
    const certificate = `
MIIBqjCCARagAwIBAgIBCzAKBggqhQMHAQEDAzASMRAwDgYDVQQDEwdFeGFtcGxl
MCAXDTAxMDEwMTAwMDAwMFoYDzIwNTAxMjMxMDAwMDAwWjASMRAwDgYDVQQDEwdF
eGFtcGxlMIGgMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAAOBhAAEgYDh7zDVLGEz
3dmdHVxBRVz3302LTJJbvGmvFDPRVlhRWt0hRoUMMlxbgcEzvmVaqMTUQOe5io1Z
SHsMdpa8xV0R7L53NqnsNX/y/TmTH04RTLjNo1knCsfw5/9D2UGUGeph/Sq3f12f
Y1I9O1CgT2PioM9Rt8E63CFWDwvUDMnHN6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAK
BggqhQMHAQEDAwOBgQBBVwPYkvGl8/aMQ1MYmn7iB7gLVjHvnUlSmk1rVCws+hWq
LqzxH0cP3n2VSFaQPDX9j5Ve8wDZXHdTSnJKDu5wL4b6YKCBCRoj3XleHjxonuUS
o8gu4NzCZDx47qj8rNNUklWEhrIPHJ7Bl8kGmYUCYMk7y82cXDMX4ZNE4XOuNg==`;

    proceedCertitificate(Uint8Array.fromBase64(certificate), privateKey);
});

test("[X.509] GOST R 34.10-2012 (Root CA)", () => {
    // ПАК «Минкомсвязь России» -> серийный номер: 4E6D478B26F27D657F768E025CE3D393
    // https://e-trust.gosuslugi.ru/app/scc/portal/api/v1/portal/ca/download/4BC6DC14D97010C41A26E058AD851F81C842415A
    const certificate = `
MIIFFDCCBMGgAwIBAgIQTm1HiybyfWV/do4CXOPTkzAKBggqhQMHAQEDAjCCASQxHjAcBgkqhkiG9w0B
CQEWD2RpdEBtaW5zdnlhei5ydTELMAkGA1UEBhMCUlUxGDAWBgNVBAgMDzc3INCc0L7RgdC60LLQsDEZ
MBcGA1UEBwwQ0LMuINCc0L7RgdC60LLQsDEuMCwGA1UECQwl0YPQu9C40YbQsCDQotCy0LXRgNGB0LrQ
sNGPLCDQtNC+0LwgNzEsMCoGA1UECgwj0JzQuNC90LrQvtC80YHQstGP0LfRjCDQoNC+0YHRgdC40Lgx
GDAWBgUqhQNkARINMTA0NzcwMjAyNjcwMTEaMBgGCCqFAwOBAwEBEgwwMDc3MTA0NzQzNzUxLDAqBgNV
BAMMI9Cc0LjQvdC60L7QvNGB0LLRj9C30Ywg0KDQvtGB0YHQuNC4MB4XDTE4MDcwNjEyMTgwNloXDTM2
MDcwMTEyMTgwNlowggEkMR4wHAYJKoZIhvcNAQkBFg9kaXRAbWluc3Z5YXoucnUxCzAJBgNVBAYTAlJV
MRgwFgYDVQQIDA83NyDQnNC+0YHQutCy0LAxGTAXBgNVBAcMENCzLiDQnNC+0YHQutCy0LAxLjAsBgNV
BAkMJdGD0LvQuNGG0LAg0KLQstC10YDRgdC60LDRjywg0LTQvtC8IDcxLDAqBgNVBAoMI9Cc0LjQvdC6
0L7QvNGB0LLRj9C30Ywg0KDQvtGB0YHQuNC4MRgwFgYFKoUDZAESDTEwNDc3MDIwMjY3MDExGjAYBggq
hQMDgQMBARIMMDA3NzEwNDc0Mzc1MSwwKgYDVQQDDCPQnNC40L3QutC+0LzRgdCy0Y/Qt9GMINCg0L7R
gdGB0LjQuDBmMB8GCCqFAwcBAQEBMBMGByqFAwICIwEGCCqFAwcBAQICA0MABEB1OSpFp7milX33EP0i
kge6HbZacYp9fVj8sUa5RWFXrB27SKX5SvtIGepqKev69RSYeHHKR+jT9YX2NuSK9wONo4IBwjCCAb4w
gfUGBSqFA2RwBIHrMIHoDDTQn9CQ0JrQnCDCq9Ca0YDQuNC/0YLQvtCf0YDQviBIU03CuyDQstC10YDR
gdC40LggMi4wDEPQn9CQ0JogwqvQk9C+0LvQvtCy0L3QvtC5INGD0LTQvtGB0YLQvtCy0LXRgNGP0Y7R
idC40Lkg0YbQtdC90YLRgMK7DDXQl9Cw0LrQu9GO0YfQtdC90LjQtSDihJYgMTQ5LzMvMi8yLzIzINC+
0YIgMDIuMDMuMjAxOAw00JfQsNC60LvRjtGH0LXQvdC40LUg4oSWIDE0OS83LzYvMTA1INC+0YIgMjcu
MDYuMjAxODA/BgUqhQNkbwQ2DDTQn9CQ0JrQnCDCq9Ca0YDQuNC/0YLQvtCf0YDQviBIU03CuyDQstC1
0YDRgdC40LggMi4wMEMGA1UdIAQ8MDowCAYGKoUDZHEBMAgGBiqFA2RxAjAIBgYqhQNkcQMwCAYGKoUD
ZHEEMAgGBiqFA2RxBTAGBgRVHSAAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBTCVPG0a9RMt+BtNrQjkPH+wzybBjAKBggqhQMHAQEDAgNBAJr6/eI7rHL7+FsQnoH2i6DVxqal
bIxLKj05edpZGPLLb6B2PTAMya7pSt9hb8QnFABgsR4IE5gT4VVkDWbX/n4=`;

    proceedCertitificate(Uint8Array.fromBase64(certificate));
});

test("[X.509] GOST R 34.10-2012 (Root CA #2)", () => {
    // ПАК «Минцифры России» -> серийный номер: 18C34DF536B9FDE22979E55C48083650
    // https://e-trust.gosuslugi.ru/app/scc/portal/api/v1/portal/ca/download/2FDEDE3B528B3DD0CBAD26D1628F40A5AB596F2F
    const certificate = `
MIIF6zCCBZigAwIBAgIQGMNN9Ta5/eIpeeVcSAg2UDAKBggqhQMHAQEDAjCCATsxITAfBgkqhkiG9w0B
CQEWEmRpdEBkaWdpdGFsLmdvdi5ydTELMAkGA1UEBhMCUlUxGDAWBgNVBAgMDzc3INCc0L7RgdC60LLQ
sDEZMBcGA1UEBwwQ0LMuINCc0L7RgdC60LLQsDFTMFEGA1UECQxK0J/RgNC10YHQvdC10L3RgdC60LDR
jyDQvdCw0LHQtdGA0LXQttC90LDRjywg0LTQvtC8IDEwLCDRgdGC0YDQvtC10L3QuNC1IDIxJjAkBgNV
BAoMHdCc0LjQvdGG0LjRhNGA0Ysg0KDQvtGB0YHQuNC4MRgwFgYFKoUDZAESDTEwNDc3MDIwMjY3MDEx
FTATBgUqhQNkBBIKNzcxMDQ3NDM3NTEmMCQGA1UEAwwd0JzQuNC90YbQuNGE0YDRiyDQoNC+0YHRgdC4
0LgwHhcNMjYwMjAyMDk1NTU0WhcNNDQwMjAyMDk1NTU0WjCCATsxITAfBgkqhkiG9w0BCQEWEmRpdEBk
aWdpdGFsLmdvdi5ydTELMAkGA1UEBhMCUlUxGDAWBgNVBAgMDzc3INCc0L7RgdC60LLQsDEZMBcGA1UE
BwwQ0LMuINCc0L7RgdC60LLQsDFTMFEGA1UECQxK0J/RgNC10YHQvdC10L3RgdC60LDRjyDQvdCw0LHQ
tdGA0LXQttC90LDRjywg0LTQvtC8IDEwLCDRgdGC0YDQvtC10L3QuNC1IDIxJjAkBgNVBAoMHdCc0LjQ
vdGG0LjRhNGA0Ysg0KDQvtGB0YHQuNC4MRgwFgYFKoUDZAESDTEwNDc3MDIwMjY3MDExFTATBgUqhQNk
BBIKNzcxMDQ3NDM3NTEmMCQGA1UEAwwd0JzQuNC90YbQuNGE0YDRiyDQoNC+0YHRgdC40LgwZjAfBggq
hQMHAQEBATATBgcqhQMCAiMBBggqhQMHAQECAgNDAARAOlhswj7Pnz34kJ+O81FNUAAxUf7gHbRnAMto
JnMoSyZHVHMlJDYeRar7rWlxXbOkN0hOUzCXgvDWt02Vbc+JKaOCAmswggJnMIIBLQYFKoUDZHAEggEi
MIIBHgxp0J/QkNCa0JwgwqvQmtGA0LjQv9GC0L7Qn9GA0L4gSFNNwrsg0LLQtdGA0YHQuNGPIDIuMCAo
0LrQvtC80L/Qu9C10LrRgtCw0YbQuNGPIDEpKNC40YHQv9C+0LvQvdC10L3QuNC1IDEpDEPQn9CQ0Jog
wqvQk9C+0LvQvtCy0L3QvtC5INGD0LTQvtGB0YLQvtCy0LXRgNGP0Y7RidC40Lkg0YbQtdC90YLRgMK7
DDbQl9Cw0LrQu9GO0YfQtdC90LjQtSDihJYgMTQ5LzMvMi8xLzIxMCDQvtGCIDMxLjAxLjIwMjMMNNCX
0LDQutC70Y7Rh9C10L3QuNC1IOKEliAxNDkvNy82LzQ0NyDQvtGCIDMwLjA5LjIwMjUwdAYFKoUDZG8E
awxp0J/QkNCa0JwgwqvQmtGA0LjQv9GC0L7Qn9GA0L4gSFNNwrsg0LLQtdGA0YHQuNGPIDIuMCAo0LrQ
vtC80L/Qu9C10LrRgtCw0YbQuNGPIDEpKNC40YHQv9C+0LvQvdC10L3QuNC1IDEpMAwGBSqFA2RyBAMC
AQAwQwYDVR0gBDwwOjAIBgYqhQNkcQEwCAYGKoUDZHECMAgGBiqFA2RxAzAIBgYqhQNkcQQwCAYGKoUD
ZHEFMAYGBFUdIAAwDgYDVR0PAQH/BAQDAgEGMCsGA1UdEAQkMCKADzIwMjYwMjAyMDk1NTU0WoEPMjAz
NDAyMDIwOTU1NTRaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMFFwA33zK3KCN8nTOEzuIoh+8tT
MAoGCCqFAwcBAQMCA0EA5Ut/qWZRPqet7G/mMKM7rp0P319KF0V09kId5GT/AClPLy87uaw2s5+nVDcf
tXlmoAcK5cHYxGeGIoU3lxdN6w==`;

    proceedCertitificate(Uint8Array.fromBase64(certificate));
});