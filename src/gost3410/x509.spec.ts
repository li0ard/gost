import { concatBytes, hexToBytes, type TArg } from "@noble/hashes/utils.js";
import { test, expect } from "bun:test";
import { gost3410 } from ".";
import { AsnConvert, AsnProp, AsnPropTypes, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { getCurveByOid, getHashByOid } from "../oids";

class PublicKeyParameters {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    curve!: string;

    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    digest!: string;
}

const _4 = new Uint8Array([4]);

const proceedCertitificate = (
    privateKey: TArg<Uint8Array>,
    certificate: TArg<Uint8Array>,
    checkPublicKey: boolean = true
) => {
    const parsed = AsnConvert.parse(certificate, Certificate);
    const parameters = AsnConvert.parse(parsed.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters!, PublicKeyParameters);
    
    const signer = getCurveByOid(parameters.curve);
    if(!signer) throw new Error("Invalid curve parameters");

    const digest = getHashByOid(parameters.digest);
    if(!digest) throw new Error("Invalid hash function");

    // Unfortunately, GOST doesn't have unificated serialization
    const spk = signer.utils.swapPoint(new Uint8Array(
        AsnConvert.parse(parsed.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, OctetString).buffer
    ).reverse());

    if(checkPublicKey) {
        const pk = signer.getPublicKey(privateKey, false);
        // Unfortunately, GOST doesn't have unificated serialization
        expect(pk.subarray(1)).toStrictEqual(spk);
    }

    expect(signer.verify(
        concatBytes(_4, spk),
        digest(new Uint8Array(parsed.tbsCertificateRaw!)).reverse(),
        signer.utils.swapPoint(new Uint8Array(parsed.signatureValue))
    )).toBeTrue();
}

test("[X.509] GOST R 34.10-2012 256 bit", () => {
    const privateKey = hexToBytes("BFCF1D623E5CDD3032A7C6EABB4A923C46E43D640FFEAAF2C3ED39A8FA399924");
    const certificate = `
MIICYjCCAg+gAwIBAgIBATAKBggqhQMHAQEDAjBWMSkwJwYJKoZIhvcNAQkBFhpH
b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw
MTIgKDI1NiBiaXQpIGV4YW1wbGUwHhcNMTMxMTA1MTQwMjM3WhcNMzAxMTAxMTQw
MjM3WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv
bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDI1NiBiaXQpIGV4YW1wbGUwZjAf
BggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAut/Qw1MUq9KPqkdH
C2xAF3K7TugHfo9n525D2s5mFZdD5pwf90/i4vF0mFmr9nfRwMYP4o0Pg1mOn5Rl
aXNYraOBwDCBvTAdBgNVHQ4EFgQU1fIeN1HaPbw+XWUzbkJ+kHJUT0AwCwYDVR0P
BAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYDVR0BBHcwdYAU1fIeN1HaPbw+XWUz
bkJ+kHJUT0ChWqRYMFYxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4
YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0MTAtMjAxMiAoMjU2IGJpdCkgZXhh
bXBsZYIBATAKBggqhQMHAQEDAgNBAF5bm4BbARR6hJLEoWJkOsYV3Hd7kXQQjz3C
dqQfmHrz6TI6Xojdh/t8ckODv/587NS5/6KsM77vc6Wh90NAT2s=
    `;

    proceedCertitificate(privateKey, Uint8Array.fromBase64(certificate));
});

test("[X.509] GOST R 34.10-2012 512 bit", () => {
    const privateKey = hexToBytes("3FC01CDCD4EC5F972EB482774C41E66DB7F380528DFE9E67992BA05AEE462435757530E641077CE587B976C8EEB48C48FD33FD175F0C7DE6A44E014E6BCB074B");
    const certificate = `
MIIC6DCCAlSgAwIBAgIBATAKBggqhQMHAQEDAzBWMSkwJwYJKoZIhvcNAQkBFhpH
b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw
MTIgKDUxMiBiaXQpIGV4YW1wbGUwHhcNMTMxMDA0MDczNjA0WhcNMzAxMDAxMDcz
NjA0WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv
bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDUxMiBiaXQpIGV4YW1wbGUwgaow
IQYIKoUDBwEBAQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYATGQ9VCiM5
FRGCQ8MEz2F1dANqhaEuywa8CbxOnTvaGJpFQVXQwkwvLFAKh7hk542vOEtxpKtT
CXfGf84nRhMH/Q9bZeAc2eO/yhxrsQhTBufa1Fuou2oe/jUOaG6RAtUUvRzhNTpp
RGGl1+EIY2vzzUua9j9Ol/gAoy/LNKQIfqOBwDCBvTAdBgNVHQ4EFgQUPcbTRXJZ
nHtjj+eBP7b5lcTMekIwCwYDVR0PBAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYD
VR0BBHcwdYAUPcbTRXJZnHtjj+eBP7b5lcTMekKhWqRYMFYxKTAnBgkqhkiG9w0B
CQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0
MTAtMjAxMiAoNTEyIGJpdCkgZXhhbXBsZYIBATAKBggqhQMHAQEDAwOBgQBObS7o
ppPTXzHyVR1DtPa8b57nudJzI4czhsfeX5HDntOq45t9B/qSs8dC6eGxbhHZ9zCO
SFtxWYdmg0au8XI9Xb8vTC1qdwWID7FFjMWDNQZb6lYh/J+8F2xKylvB5nIlRZqO
o3eUNFkNyHJwQCk2WoOlO16zwGk2tdKH4KmD5w==
    `;

    proceedCertitificate(privateKey, Uint8Array.fromBase64(certificate));
});

test("[X.509] GOST R 34.10-2012 (Root CA)", () => {
    // ПАК «Головной удостоверяющий центр» -> серийный номер: 4E6D478B26F27D657F768E025CE3D393
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
bIxLKj05edpZGPLLb6B2PTAMya7pSt9hb8QnFABgsR4IE5gT4VVkDWbX/n4=
    `
    proceedCertitificate(new Uint8Array(), Uint8Array.fromBase64(certificate), false);
});