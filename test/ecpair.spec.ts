import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type {
    Bytes32,
    CryptoBackend,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    TinySecp256k1Interface,
    XOnlyPublicKey,
} from '../src/index.js';
import {
    assertBytes32,
    assertMessageHash,
    assertPrivateKey,
    assertPublicKey,
    assertXOnlyPublicKey,
    bytesEqual,
    compareBytes,
    concatBytes,
    createBytes20,
    createBytes32,
    createLegacyBackend,
    createMessageHash,
    createNobleBackend,
    createPrivateKey,
    createPublicKey,
    createSatoshi,
    createSchnorrSignature,
    createSignature,
    createXOnlyPublicKey,
    decodeWIF,
    EC_N,
    EC_P,
    ECPairSigner,
    encodeWIF,
    fromHexInternal,
    isBytes20,
    isBytes32,
    isMessageHash,
    isPrivateKey,
    isPublicKey,
    isSatoshi,
    isSchnorrSignature,
    isSignature,
    isXOnlyPublicKey,
    isZeroBytes,
    LegacyBackend,
    NobleBackend,
    SATOSHI_MAX,
    SignerCapability,
    toHex,
    verifyCryptoBackend,
} from '../src/index.js';
import * as networks from './networks.js';
import * as tinysecp from 'tiny-secp256k1';
import fixtures from './fixtures/ecpair.json' with { type: 'json' };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function h(hex: string): Uint8Array {
    return fromHexInternal(hex);
}

function sha256(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash('sha256').update(data).digest());
}

function tapTweakHash(pubKey: Uint8Array, tweak?: Uint8Array): Uint8Array {
    const data = tweak ? concatBytes(pubKey, tweak) : pubKey;
    const tagHash = sha256(new TextEncoder().encode('TapTweak'));
    const tag = concatBytes(tagHash, tagHash);
    return sha256(concatBytes(tag, data));
}

const ZERO = new Uint8Array(32);
const ONE = h('0000000000000000000000000000000000000000000000000000000000000001');
const GROUP_ORDER = h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const GROUP_ORDER_LESS_1 = h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140');

const NETWORKS_LIST = Object.values(networks) as readonly (typeof networks.bitcoin)[];

function defined<T>(value: T | undefined | null): T {
    if (value == null) throw new Error('expected defined value');
    return value;
}

function mockBackend(
    base: CryptoBackend,
    overrides: Partial<Record<keyof CryptoBackend, unknown>>,
): CryptoBackend {
    const mock: Record<string, unknown> = {};
    const keys: (keyof CryptoBackend)[] = [
        'isPrivate',
        'isPoint',
        'pointFromScalar',
        'pointCompress',
        'pointAddScalar',
        'xOnlyPointAddTweak',
        'privateAdd',
        'privateNegate',
        'sign',
        'verify',
        'signSchnorr',
        'verifySchnorr',
    ];
    for (const key of keys) {
        if (key in overrides) {
            mock[key] = overrides[key];
        } else {
            const val = base[key];
            mock[key] = typeof val === 'function' ? val.bind(base) : val;
        }
    }
    return mock as unknown as CryptoBackend;
}

// ---------------------------------------------------------------------------
// 1. types.ts — byte utilities, type guards, assertions, creation
// ---------------------------------------------------------------------------

describe('types', () => {
    describe('fromHexInternal', () => {
        it('decodes valid hex', () => {
            expect(fromHexInternal('deadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
        });

        it('decodes uppercase hex', () => {
            expect(fromHexInternal('DEADBEEF')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
        });

        it('decodes empty string', () => {
            expect(fromHexInternal('')).toEqual(new Uint8Array(0));
        });

        it('throws on odd-length hex', () => {
            expect(() => fromHexInternal('abc')).toThrow('odd-length hex string');
        });

        it('throws on invalid hex characters', () => {
            expect(() => fromHexInternal('zzzz')).toThrow('invalid hex character');
        });
    });

    describe('isZeroBytes', () => {
        it('returns true for all-zero bytes', () => {
            expect(isZeroBytes(new Uint8Array(32))).toBe(true);
        });

        it('returns true for empty array', () => {
            expect(isZeroBytes(new Uint8Array(0))).toBe(true);
        });

        it('returns false for non-zero bytes', () => {
            expect(isZeroBytes(ONE)).toBe(false);
        });
    });

    describe('compareBytes', () => {
        it('returns 0 for equal arrays', () => {
            expect(compareBytes(ONE, ONE)).toBe(0);
        });

        it('returns -1 when a < b', () => {
            expect(compareBytes(ONE, GROUP_ORDER)).toBe(-1);
        });

        it('returns 1 when a > b', () => {
            expect(compareBytes(GROUP_ORDER, ONE)).toBe(1);
        });

        it('returns -1 when a is shorter', () => {
            expect(compareBytes(new Uint8Array(1), new Uint8Array(2))).toBe(-1);
        });

        it('returns 1 when a is longer', () => {
            expect(compareBytes(new Uint8Array(2), new Uint8Array(1))).toBe(1);
        });
    });

    describe('bytesEqual', () => {
        it('returns true for equal arrays', () => {
            expect(bytesEqual(ONE, ONE)).toBe(true);
        });

        it('returns false for different values', () => {
            expect(bytesEqual(ONE, ZERO)).toBe(false);
        });

        it('returns false for different lengths', () => {
            expect(bytesEqual(new Uint8Array(1), new Uint8Array(2))).toBe(false);
        });
    });

    describe('toHex', () => {
        it('converts bytes to hex', () => {
            expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
        });

        it('pads single digits', () => {
            expect(toHex(new Uint8Array([0x0a]))).toBe('0a');
        });

        it('handles empty array', () => {
            expect(toHex(new Uint8Array(0))).toBe('');
        });
    });

    describe('concatBytes', () => {
        it('concatenates arrays', () => {
            const a = new Uint8Array([1, 2]);
            const b = new Uint8Array([3, 4]);
            expect(concatBytes(a, b)).toEqual(new Uint8Array([1, 2, 3, 4]));
        });

        it('handles empty arrays', () => {
            expect(concatBytes(new Uint8Array(0), new Uint8Array([1]))).toEqual(
                new Uint8Array([1]),
            );
        });

        it('handles no arguments', () => {
            expect(concatBytes()).toEqual(new Uint8Array(0));
        });
    });

    describe('constants', () => {
        it('EC_N is the secp256k1 curve order', () => {
            expect(EC_N).toBe(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n);
        });

        it('EC_P is the secp256k1 field prime', () => {
            expect(EC_P).toBe(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn);
        });

        it('SATOSHI_MAX is 21 million BTC in sats', () => {
            expect(SATOSHI_MAX).toBe(2100000000000000n);
        });
    });

    describe('type guards', () => {
        describe('isBytes32', () => {
            it('accepts 32-byte Uint8Array', () => {
                expect(isBytes32(new Uint8Array(32))).toBe(true);
            });

            it('rejects wrong length', () => {
                expect(isBytes32(new Uint8Array(16))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isBytes32('not bytes')).toBe(false);
            });
        });

        describe('isBytes20', () => {
            it('accepts 20-byte Uint8Array', () => {
                expect(isBytes20(new Uint8Array(20))).toBe(true);
            });

            it('rejects wrong length', () => {
                expect(isBytes20(new Uint8Array(32))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isBytes20(42)).toBe(false);
            });
        });

        describe('isPrivateKey', () => {
            it('accepts valid private key', () => {
                expect(isPrivateKey(ONE)).toBe(true);
            });

            it('accepts n-1', () => {
                expect(isPrivateKey(GROUP_ORDER_LESS_1)).toBe(true);
            });

            it('rejects zero', () => {
                expect(isPrivateKey(ZERO)).toBe(false);
            });

            it('rejects n', () => {
                expect(isPrivateKey(GROUP_ORDER)).toBe(false);
            });

            it('rejects n+1', () => {
                expect(
                    isPrivateKey(
                        h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142'),
                    ),
                ).toBe(false);
            });

            it('rejects wrong length', () => {
                expect(isPrivateKey(new Uint8Array(16))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isPrivateKey('string')).toBe(false);
            });
        });

        describe('isPublicKey', () => {
            it('accepts compressed 02 prefix', () => {
                expect(
                    isPublicKey(
                        h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
                    ),
                ).toBe(true);
            });

            it('accepts compressed 03 prefix', () => {
                expect(
                    isPublicKey(
                        h('0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
                    ),
                ).toBe(true);
            });

            it('accepts uncompressed 04 prefix', () => {
                expect(
                    isPublicKey(
                        h(
                            '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
                        ),
                    ),
                ).toBe(true);
            });

            it('accepts hybrid 06 prefix', () => {
                const key = new Uint8Array(65);
                key[0] = 0x06;
                key[1] = 1;
                expect(isPublicKey(key)).toBe(true);
            });

            it('accepts hybrid 07 prefix', () => {
                const key = new Uint8Array(65);
                key[0] = 0x07;
                key[1] = 1;
                expect(isPublicKey(key)).toBe(true);
            });

            it('rejects invalid prefix', () => {
                const key = new Uint8Array(33);
                key[0] = 0x05;
                expect(isPublicKey(key)).toBe(false);
            });

            it('rejects wrong length for compressed', () => {
                const key = new Uint8Array(34);
                key[0] = 0x02;
                expect(isPublicKey(key)).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isPublicKey('string')).toBe(false);
            });
        });

        describe('isXOnlyPublicKey', () => {
            it('accepts valid 32-byte non-zero', () => {
                expect(isXOnlyPublicKey(ONE)).toBe(true);
            });

            it('rejects zero', () => {
                expect(isXOnlyPublicKey(ZERO)).toBe(false);
            });

            it('rejects wrong length', () => {
                expect(isXOnlyPublicKey(new Uint8Array(33))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isXOnlyPublicKey(42)).toBe(false);
            });
        });

        describe('isSignature', () => {
            it('accepts 8-byte signature', () => {
                expect(isSignature(new Uint8Array(8))).toBe(true);
            });

            it('accepts 73-byte signature', () => {
                expect(isSignature(new Uint8Array(73))).toBe(true);
            });

            it('accepts 64-byte signature', () => {
                expect(isSignature(new Uint8Array(64))).toBe(true);
            });

            it('rejects 7-byte array', () => {
                expect(isSignature(new Uint8Array(7))).toBe(false);
            });

            it('rejects 74-byte array', () => {
                expect(isSignature(new Uint8Array(74))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isSignature('string')).toBe(false);
            });
        });

        describe('isSchnorrSignature', () => {
            it('accepts 64-byte array', () => {
                expect(isSchnorrSignature(new Uint8Array(64))).toBe(true);
            });

            it('rejects 63-byte array', () => {
                expect(isSchnorrSignature(new Uint8Array(63))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isSchnorrSignature(null)).toBe(false);
            });
        });

        describe('isMessageHash', () => {
            it('accepts 32-byte array', () => {
                expect(isMessageHash(new Uint8Array(32))).toBe(true);
            });

            it('rejects wrong length', () => {
                expect(isMessageHash(new Uint8Array(31))).toBe(false);
            });

            it('rejects non-Uint8Array', () => {
                expect(isMessageHash(undefined)).toBe(false);
            });
        });

        describe('isSatoshi', () => {
            it('accepts zero', () => {
                expect(isSatoshi(0n)).toBe(true);
            });

            it('accepts max', () => {
                expect(isSatoshi(SATOSHI_MAX)).toBe(true);
            });

            it('rejects negative', () => {
                expect(isSatoshi(-1n)).toBe(false);
            });

            it('rejects over max', () => {
                expect(isSatoshi(SATOSHI_MAX + 1n)).toBe(false);
            });

            it('rejects non-bigint', () => {
                expect(isSatoshi(42)).toBe(false);
            });
        });
    });

    describe('assertion functions', () => {
        describe('assertBytes32', () => {
            it('passes for valid input', () => {
                expect(() => assertBytes32(new Uint8Array(32))).not.toThrow();
            });

            it('throws for non-Uint8Array', () => {
                expect(() => assertBytes32('string')).toThrow('expected Uint8Array');
            });

            it('throws for wrong length', () => {
                expect(() => assertBytes32(new Uint8Array(16))).toThrow(
                    'expected 32 bytes, got 16',
                );
            });
        });

        describe('assertPrivateKey', () => {
            it('passes for valid key', () => {
                expect(() => assertPrivateKey(ONE)).not.toThrow();
            });

            it('throws for non-Uint8Array', () => {
                expect(() => assertPrivateKey(42)).toThrow('expected Uint8Array');
            });

            it('throws for wrong length', () => {
                expect(() => assertPrivateKey(new Uint8Array(16))).toThrow(
                    'expected 32 bytes, got 16',
                );
            });

            it('throws for zero key', () => {
                expect(() => assertPrivateKey(ZERO)).toThrow('key is zero');
            });

            it('throws for key >= n', () => {
                expect(() => assertPrivateKey(GROUP_ORDER)).toThrow('key not in range');
            });
        });

        describe('assertPublicKey', () => {
            it('passes for valid compressed key', () => {
                expect(() =>
                    assertPublicKey(
                        h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
                    ),
                ).not.toThrow();
            });

            it('throws for non-Uint8Array', () => {
                expect(() => assertPublicKey('string')).toThrow('expected Uint8Array');
            });

            it('throws for invalid format', () => {
                expect(() => assertPublicKey(new Uint8Array(33))).toThrow(
                    'invalid SEC1 public key',
                );
            });

            it('throws for empty Uint8Array', () => {
                expect(() => assertPublicKey(new Uint8Array(0))).toThrow('invalid SEC1 public key');
            });
        });

        describe('assertXOnlyPublicKey', () => {
            it('passes for valid key', () => {
                expect(() => assertXOnlyPublicKey(ONE)).not.toThrow();
            });

            it('throws for non-Uint8Array', () => {
                expect(() => assertXOnlyPublicKey('string')).toThrow('expected Uint8Array');
            });

            it('throws for wrong length', () => {
                expect(() => assertXOnlyPublicKey(new Uint8Array(16))).toThrow('expected 32 bytes');
            });

            it('throws for zero key', () => {
                expect(() => assertXOnlyPublicKey(ZERO)).toThrow('key is zero');
            });
        });

        describe('assertMessageHash', () => {
            it('passes for valid hash', () => {
                expect(() => assertMessageHash(new Uint8Array(32))).not.toThrow();
            });

            it('throws for non-Uint8Array', () => {
                expect(() => assertMessageHash(null)).toThrow('expected Uint8Array');
            });

            it('throws for wrong length', () => {
                expect(() => assertMessageHash(new Uint8Array(16))).toThrow('expected 32 bytes');
            });
        });
    });

    describe('creation functions', () => {
        it('createBytes32 accepts valid input', () => {
            const b = createBytes32(new Uint8Array(32));
            expect(b.length).toBe(32);
        });

        it('createBytes32 rejects invalid input', () => {
            expect(() => createBytes32(new Uint8Array(16))).toThrow();
        });

        it('createBytes20 accepts valid input', () => {
            const b = createBytes20(new Uint8Array(20));
            expect(b.length).toBe(20);
        });

        it('createBytes20 rejects wrong length', () => {
            expect(() => createBytes20(new Uint8Array(32))).toThrow('expected 20 bytes');
        });

        it('createBytes20 rejects non-Uint8Array', () => {
            expect(() => createBytes20('string' as unknown as Uint8Array)).toThrow(
                'expected 20 bytes',
            );
        });

        it('createPrivateKey accepts valid key', () => {
            const k = createPrivateKey(ONE);
            expect(bytesEqual(k, ONE)).toBe(true);
        });

        it('createPrivateKey rejects zero', () => {
            expect(() => createPrivateKey(ZERO)).toThrow();
        });

        it('createPublicKey accepts valid key', () => {
            const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
            expect(createPublicKey(pub).length).toBe(33);
        });

        it('createPublicKey rejects invalid key', () => {
            expect(() => createPublicKey(new Uint8Array(33))).toThrow();
        });

        it('createXOnlyPublicKey accepts valid key', () => {
            expect(createXOnlyPublicKey(ONE).length).toBe(32);
        });

        it('createXOnlyPublicKey rejects zero', () => {
            expect(() => createXOnlyPublicKey(ZERO)).toThrow();
        });

        it('createSignature accepts valid range', () => {
            expect(createSignature(new Uint8Array(64)).length).toBe(64);
        });

        it('createSignature rejects out of range', () => {
            expect(() => createSignature(new Uint8Array(7))).toThrow('expected 8-73 bytes');
        });

        it('createSchnorrSignature accepts 64 bytes', () => {
            expect(createSchnorrSignature(new Uint8Array(64)).length).toBe(64);
        });

        it('createSchnorrSignature rejects wrong length', () => {
            expect(() => createSchnorrSignature(new Uint8Array(63))).toThrow('expected 64 bytes');
        });

        it('createMessageHash accepts 32 bytes', () => {
            expect(createMessageHash(new Uint8Array(32)).length).toBe(32);
        });

        it('createMessageHash rejects wrong length', () => {
            expect(() => createMessageHash(new Uint8Array(16))).toThrow();
        });

        it('createSatoshi accepts valid value', () => {
            expect(createSatoshi(0n)).toBe(0n);
            expect(createSatoshi(SATOSHI_MAX)).toBe(SATOSHI_MAX);
        });

        it('createSatoshi rejects out of range', () => {
            expect(() => createSatoshi(-1n)).toThrow('out of range');
            expect(() => createSatoshi(SATOSHI_MAX + 1n)).toThrow('out of range');
        });
    });
});

// ---------------------------------------------------------------------------
// 2. networks.ts
// ---------------------------------------------------------------------------

describe('networks', () => {
    it('bitcoin has correct wif', () => {
        expect(networks.bitcoin.wif).toBe(0x80);
    });

    it('bitcoin has correct bech32', () => {
        expect(networks.bitcoin.bech32).toBe('bc');
    });

    it('bitcoin has correct bech32Opnet', () => {
        expect(networks.bitcoin.bech32Opnet).toBe('op');
    });

    it('bitcoin has correct bip32 versions', () => {
        expect(networks.bitcoin.bip32.public).toBe(0x0488b21e);
        expect(networks.bitcoin.bip32.private).toBe(0x0488ade4);
    });

    it('testnet has correct wif', () => {
        expect(networks.testnet.wif).toBe(0xef);
    });

    it('testnet has correct bech32', () => {
        expect(networks.testnet.bech32).toBe('tb');
    });

    it('testnet has correct bech32Opnet', () => {
        expect(networks.testnet.bech32Opnet).toBe('opt');
    });

    it('regtest has correct bech32', () => {
        expect(networks.regtest.bech32).toBe('bcrt');
    });

    it('regtest has correct bech32Opnet', () => {
        expect(networks.regtest.bech32Opnet).toBe('opr');
    });

    it('regtest shares testnet wif', () => {
        expect(networks.regtest.wif).toBe(networks.testnet.wif);
    });
});

// ---------------------------------------------------------------------------
// 3. capability.ts
// ---------------------------------------------------------------------------

describe('SignerCapability', () => {
    it('has all expected values as power-of-2 flags', () => {
        expect(SignerCapability.EcdsaSign).toBe(1 << 0);
        expect(SignerCapability.EcdsaVerify).toBe(1 << 1);
        expect(SignerCapability.SchnorrSign).toBe(1 << 2);
        expect(SignerCapability.SchnorrVerify).toBe(1 << 3);
        expect(SignerCapability.PrivateKeyExport).toBe(1 << 4);
        expect(SignerCapability.PublicKeyTweak).toBe(1 << 5);
        expect(SignerCapability.HdDerivation).toBe(1 << 6);
    });
});

// ---------------------------------------------------------------------------
// 4. NobleBackend
// ---------------------------------------------------------------------------

describe('NobleBackend', () => {
    const backend = createNobleBackend();

    it('createNobleBackend returns a NobleBackend instance', () => {
        expect(backend).toBeInstanceOf(NobleBackend);
    });

    describe('isPrivate', () => {
        it('accepts valid scalar', () => {
            expect(backend.isPrivate(ONE)).toBe(true);
        });

        it('accepts n-1', () => {
            expect(backend.isPrivate(GROUP_ORDER_LESS_1)).toBe(true);
        });

        it('rejects zero', () => {
            expect(backend.isPrivate(ZERO)).toBe(false);
        });

        it('rejects n', () => {
            expect(backend.isPrivate(GROUP_ORDER)).toBe(false);
        });
    });

    describe('isPoint', () => {
        it('accepts generator point', () => {
            expect(
                backend.isPoint(
                    h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
                ),
            ).toBe(true);
        });

        it('rejects invalid point', () => {
            expect(
                backend.isPoint(
                    h('030000000000000000000000000000000000000000000000000000000000000005'),
                ),
            ).toBe(false);
        });

        it('rejects empty', () => {
            expect(backend.isPoint(new Uint8Array(0))).toBe(false);
        });
    });

    describe('pointFromScalar', () => {
        it('derives known public key', () => {
            const pub = defined(backend.pointFromScalar(createPrivateKey(ONE), true));
            expect(toHex(pub)).toBe(
                '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            );
        });

        it('derives uncompressed public key', () => {
            const pub = defined(backend.pointFromScalar(createPrivateKey(ONE), false));
            expect(pub.length).toBe(65);
            expect(pub[0]).toBe(0x04);
        });

        it('returns null for invalid scalar', () => {
            const pub = backend.pointFromScalar(ZERO as PrivateKey);
            expect(pub).toBeNull();
        });
    });

    describe('pointCompress', () => {
        const uncompressed = h(
            '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
        ) as PublicKey;
        const compressed = h(
            '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        ) as PublicKey;

        it('compresses uncompressed key', () => {
            expect(bytesEqual(backend.pointCompress(uncompressed, true), compressed)).toBe(true);
        });

        it('decompresses compressed key', () => {
            expect(bytesEqual(backend.pointCompress(compressed, false), uncompressed)).toBe(true);
        });

        it('defaults to compressed when no flag provided', () => {
            const result = backend.pointCompress(uncompressed);
            expect(result.length).toBe(33);
            expect(bytesEqual(result, compressed)).toBe(true);
        });
    });

    describe('pointAddScalar', () => {
        const pub = h(
            '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        ) as PublicKey;

        it('adds a non-zero tweak', () => {
            const result = defined(backend.pointAddScalar(pub, ONE as Bytes32));
            expect(result.length).toBe(33);
        });

        it('handles zero tweak (identity)', () => {
            const result = defined(backend.pointAddScalar(pub, ZERO as Bytes32));
            expect(bytesEqual(result, pub)).toBe(true);
        });

        it('returns null for invalid tweak that results in point at infinity', () => {
            // n-1 as tweak for generator point should negate it, adding to itself gives infinity
            const result = backend.pointAddScalar(pub, GROUP_ORDER_LESS_1 as Bytes32);
            expect(result).toBeNull();
        });
    });

    describe('xOnlyPointAddTweak', () => {
        const xOnly = h(
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        ) as XOnlyPublicKey;

        it('returns result with parity', () => {
            const result = defined(backend.xOnlyPointAddTweak(xOnly, ONE as Bytes32));
            expect(result.xOnlyPubkey.length).toBe(32);
            expect([0, 1]).toContain(result.parity);
        });

        it('returns null when tweak >= N', () => {
            const result = backend.xOnlyPointAddTweak(xOnly, GROUP_ORDER as Bytes32);
            expect(result).toBeNull();
        });

        it('returns null for infinity result', () => {
            const result = backend.xOnlyPointAddTweak(xOnly, GROUP_ORDER_LESS_1 as Bytes32);
            expect(result).toBeNull();
        });
    });

    describe('privateAdd', () => {
        it('adds two scalars', () => {
            const result = backend.privateAdd(createPrivateKey(ONE), ONE as Bytes32);
            expect(
                bytesEqual(
                    defined(result),
                    h('0000000000000000000000000000000000000000000000000000000000000002'),
                ),
            ).toBe(true);
        });

        it('returns null when result is zero mod n', () => {
            const result = backend.privateAdd(createPrivateKey(ONE), GROUP_ORDER_LESS_1 as Bytes32);
            expect(result).toBeNull();
        });
    });

    describe('privateNegate', () => {
        it('negates 1 to n-1', () => {
            const result = backend.privateNegate(createPrivateKey(ONE));
            expect(bytesEqual(result, GROUP_ORDER_LESS_1)).toBe(true);
        });

        it('negates n-1 to 1', () => {
            const result = backend.privateNegate(createPrivateKey(GROUP_ORDER_LESS_1));
            expect(bytesEqual(result, ONE)).toBe(true);
        });
    });

    describe('sign and verify', () => {
        const privKey = createPrivateKey(ONE);
        const msgHash = createMessageHash(
            h('5e9f0a0d593efdcf78ac923bc3313e4e7d408d574354ee2b3288c0da9fbba6ed'),
        );

        it('produces a 64-byte signature', () => {
            const sig = backend.sign(msgHash, privKey);
            expect(sig.length).toBe(64);
        });

        it('sign with extraEntropy', () => {
            const sig = backend.sign(msgHash, privKey, new Uint8Array(32));
            expect(sig.length).toBe(64);
        });

        it('verify accepts valid signature', () => {
            const pub = defined(backend.pointFromScalar(privKey, true));
            const sig = backend.sign(msgHash, privKey);
            expect(backend.verify(msgHash, pub, sig)).toBe(true);
        });

        it('verify rejects invalid signature', () => {
            const pub = defined(backend.pointFromScalar(privKey, true));
            const badSig = new Uint8Array(64).fill(0xff) as Signature;
            expect(backend.verify(msgHash, pub, badSig)).toBe(false);
        });
    });

    describe('signSchnorr and verifySchnorr', () => {
        const privKey = createPrivateKey(ONE);
        const msgHash = createMessageHash(new Uint8Array(32).fill(2));

        it('produces a 64-byte Schnorr signature', () => {
            const sig = backend.signSchnorr(msgHash, privKey);
            expect(sig.length).toBe(64);
        });

        it('signSchnorr with extraEntropy', () => {
            const sig = backend.signSchnorr(msgHash, privKey, new Uint8Array(32));
            expect(sig.length).toBe(64);
        });

        it('verifySchnorr accepts valid signature', () => {
            const sig = backend.signSchnorr(msgHash, privKey);
            const pub = defined(backend.pointFromScalar(privKey, true));
            const xOnly = pub.subarray(1, 33) as XOnlyPublicKey;
            expect(backend.verifySchnorr(msgHash, xOnly, sig)).toBe(true);
        });
    });
});

// ---------------------------------------------------------------------------
// 5. LegacyBackend
// ---------------------------------------------------------------------------

describe('LegacyBackend', () => {
    const backend = createLegacyBackend(tinysecp as unknown as TinySecp256k1Interface);

    it('createLegacyBackend returns a LegacyBackend instance', () => {
        expect(backend).toBeInstanceOf(LegacyBackend);
    });

    describe('isPrivate', () => {
        it('delegates to tinysecp', () => {
            expect(backend.isPrivate(ONE)).toBe(true);
            expect(backend.isPrivate(ZERO)).toBe(false);
        });
    });

    describe('isPoint', () => {
        it('delegates to tinysecp', () => {
            expect(
                backend.isPoint(
                    h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
                ),
            ).toBe(true);
            expect(backend.isPoint(new Uint8Array(33))).toBe(false);
        });
    });

    describe('pointFromScalar', () => {
        it('derives public key', () => {
            const pub = defined(backend.pointFromScalar(createPrivateKey(ONE), true));
            expect(pub.length).toBe(33);
        });
    });

    describe('pointCompress', () => {
        it('compresses key', () => {
            const uncompressed = h(
                '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
            ) as PublicKey;
            const result = backend.pointCompress(uncompressed, true);
            expect(result.length).toBe(33);
        });
    });

    describe('pointAddScalar', () => {
        it('adds scalar to point', () => {
            const pub = h(
                '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            ) as PublicKey;
            const result = backend.pointAddScalar(pub, ONE as Bytes32);
            expect(result).not.toBeNull();
        });

        it('throws when pointAddScalar not supported', () => {
            const noAddBackend = createLegacyBackend({
                ...tinysecp,
                pointAddScalar: undefined,
            } as unknown as TinySecp256k1Interface);
            const pub = h(
                '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            ) as PublicKey;
            expect(() => noAddBackend.pointAddScalar(pub, ONE as Bytes32)).toThrow(
                'pointAddScalar not supported',
            );
        });
    });

    describe('xOnlyPointAddTweak', () => {
        it('returns tweak result', () => {
            const xOnly = h(
                '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            ) as XOnlyPublicKey;
            const result = defined(backend.xOnlyPointAddTweak(xOnly, ONE as Bytes32));
            expect(result.xOnlyPubkey.length).toBe(32);
        });

        it('returns null on failure', () => {
            const xOnly = h(
                '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            ) as XOnlyPublicKey;
            const result = backend.xOnlyPointAddTweak(xOnly, GROUP_ORDER_LESS_1 as Bytes32);
            expect(result).toBeNull();
        });
    });

    describe('privateAdd and privateNegate', () => {
        it('adds scalars', () => {
            const result = backend.privateAdd(createPrivateKey(ONE), ONE as Bytes32);
            expect(result).not.toBeNull();
        });

        it('negates scalar', () => {
            const result = backend.privateNegate(createPrivateKey(ONE));
            expect(bytesEqual(result, GROUP_ORDER_LESS_1)).toBe(true);
        });
    });

    describe('sign and verify', () => {
        const privKey = createPrivateKey(ONE);
        const msgHash = createMessageHash(ZERO);

        it('signs and verifies', () => {
            const sig = backend.sign(msgHash, privKey);
            const pub = defined(backend.pointFromScalar(privKey, true));
            expect(backend.verify(msgHash, pub, sig)).toBe(true);
        });
    });

    describe('signSchnorr and verifySchnorr', () => {
        const privKey = createPrivateKey(ONE);
        const msgHash = createMessageHash(new Uint8Array(32).fill(2));

        it('signs Schnorr', () => {
            const sig = backend.signSchnorr(msgHash, privKey);
            expect(sig.length).toBe(64);
        });

        it('verifies Schnorr', () => {
            const sig = backend.signSchnorr(msgHash, privKey);
            const pub = defined(backend.pointFromScalar(privKey, true));
            const xOnly = pub.subarray(1, 33) as XOnlyPublicKey;
            expect(backend.verifySchnorr(msgHash, xOnly, sig)).toBe(true);
        });

        it('throws signSchnorr when not supported', () => {
            const noSchnorrBackend = createLegacyBackend({
                ...tinysecp,
                signSchnorr: undefined,
            } as unknown as TinySecp256k1Interface);
            expect(() => noSchnorrBackend.signSchnorr(msgHash, privKey)).toThrow(
                'signSchnorr not supported',
            );
        });

        it('throws verifySchnorr when not supported', () => {
            const noSchnorrBackend = createLegacyBackend({
                ...tinysecp,
                verifySchnorr: undefined,
            } as unknown as TinySecp256k1Interface);
            const xOnly = ONE as XOnlyPublicKey;
            expect(() =>
                noSchnorrBackend.verifySchnorr(
                    msgHash,
                    xOnly,
                    new Uint8Array(64) as SchnorrSignature,
                ),
            ).toThrow('verifySchnorr not supported');
        });
    });

    describe('hasSchnorrSign / hasSchnorrVerify', () => {
        it('returns true when methods exist', () => {
            expect(backend.hasSchnorrSign).toBe(true);
            expect(backend.hasSchnorrVerify).toBe(true);
        });

        it('returns false when methods missing', () => {
            const noSchnorr = createLegacyBackend({
                ...tinysecp,
                signSchnorr: undefined,
                verifySchnorr: undefined,
            } as unknown as TinySecp256k1Interface);
            expect(noSchnorr.hasSchnorrSign).toBe(false);
            expect(noSchnorr.hasSchnorrVerify).toBe(false);
        });
    });
});

// ---------------------------------------------------------------------------
// 6. verifyCryptoBackend (testecc.ts)
// ---------------------------------------------------------------------------

describe('verifyCryptoBackend', () => {
    it('passes with NobleBackend', () => {
        expect(() => verifyCryptoBackend(createNobleBackend())).not.toThrow();
    });

    it('passes with LegacyBackend', () => {
        expect(() =>
            verifyCryptoBackend(createLegacyBackend(tinysecp as unknown as TinySecp256k1Interface)),
        ).not.toThrow();
    });

    it('throws on broken isPoint', () => {
        const broken = mockBackend(createNobleBackend(), {
            isPoint: () => false,
        });
        expect(() => verifyCryptoBackend(broken)).toThrow('verifyCryptoBackend');
    });

    it('throws on broken isPrivate', () => {
        const noble = createNobleBackend();
        const broken = mockBackend(noble, {
            isPrivate: () => false,
        });
        expect(() => verifyCryptoBackend(broken)).toThrow('verifyCryptoBackend');
    });

    it('passes with backend without signSchnorr', () => {
        const noble = createNobleBackend();
        const noSchnorr = mockBackend(noble, {
            signSchnorr: undefined,
        });
        expect(() => verifyCryptoBackend(noSchnorr)).not.toThrow();
    });

    it('passes with backend without verifySchnorr', () => {
        const noble = createNobleBackend();
        const noSchnorr = mockBackend(noble, {
            verifySchnorr: undefined,
        });
        expect(() => verifyCryptoBackend(noSchnorr)).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 7. WIF (wif.ts)
// ---------------------------------------------------------------------------

describe('WIF', () => {
    describe('encodeWIF', () => {
        it('encodes compressed mainnet key', () => {
            const wifStr = encodeWIF(createPrivateKey(ONE), true, networks.bitcoin);
            expect(wifStr).toBe('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn');
        });

        it('encodes uncompressed mainnet key', () => {
            const wifStr = encodeWIF(createPrivateKey(ONE), false, networks.bitcoin);
            expect(wifStr).toBe('5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf');
        });
    });

    describe('decodeWIF', () => {
        it('decodes with single network', () => {
            const result = decodeWIF(
                'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
                networks.bitcoin,
            );
            expect(bytesEqual(result.privateKey, ONE)).toBe(true);
            expect(result.compressed).toBe(true);
            expect(result.network).toBe(networks.bitcoin);
        });

        it('decodes with network array', () => {
            const result = decodeWIF(
                'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
                NETWORKS_LIST,
            );
            expect(bytesEqual(result.privateKey, ONE)).toBe(true);
            expect(result.network).toBe(networks.bitcoin);
        });

        it('throws on invalid network version', () => {
            expect(() =>
                decodeWIF('92Qba5hnyWSn5Ffcka56yMQauaWY6ZLd91Vzxbi4a9CCetaHtYj', networks.bitcoin),
            ).toThrow('Invalid network version');
        });

        it('throws on unknown network version (array)', () => {
            expect(() =>
                decodeWIF('brQnSed3Fia1w9VcbbS6ZGDgJ6ENkgwuQY2LS7pEC5bKHD1fMF', NETWORKS_LIST),
            ).toThrow('Unknown network version');
        });
    });
});

// ---------------------------------------------------------------------------
// 8. ECPairSigner — tests run with both backends
// ---------------------------------------------------------------------------

const backendEntries: [string, CryptoBackend][] = [
    ['LegacyBackend', createLegacyBackend(tinysecp as unknown as TinySecp256k1Interface)],
    ['NobleBackend', createNobleBackend()],
];

for (const [backendName, backend] of backendEntries) {
    describe(`ECPairSigner [${backendName}]`, () => {
        describe('fromPrivateKey', () => {
            it('defaults to compressed', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.compressed).toBe(true);
            });

            it('supports uncompressed option', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                    { compressed: false },
                );
                expect(kp.compressed).toBe(false);
            });

            it('supports network option', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.testnet,
                );
                expect(kp.network).toBe(networks.testnet);
            });

            it('uses provided network', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.network).toBe(networks.bitcoin);
            });

            fixtures.valid.forEach((f) => {
                it(`derives public key for ${f.WIF}`, () => {
                    const network = defined(
                        (networks as Record<string, typeof networks.bitcoin>)[f.network],
                    );
                    const kp = ECPairSigner.fromPrivateKey(
                        backend,
                        createPrivateKey(h(f.d)),
                        network,
                        { compressed: f.compressed },
                    );
                    expect(toHex(kp.publicKey)).toBe(f.Q);
                });
            });

            fixtures.invalid.fromPrivateKey.forEach((f) => {
                it(`throws ${f.exception}`, () => {
                    const rec = f as Record<string, unknown>;
                    const opts = rec['options'] as Record<string, unknown> | undefined;
                    expect(() =>
                        ECPairSigner.fromPrivateKey(
                            backend,
                            h(f.d) as PrivateKey,
                            networks.bitcoin,
                            opts as Parameters<typeof ECPairSigner.fromPrivateKey>[3],
                        ),
                    ).toThrow(new RegExp(f.exception));
                });
            });
        });

        describe('fromPublicKey', () => {
            it('creates public-key-only signer', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(kp.privateKey).toBeUndefined();
                expect(toHex(kp.publicKey)).toBe(
                    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                );
            });

            it('supports options', () => {
                const pub = h(
                    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
                );
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.testnet,
                    { compressed: false },
                );
                expect(kp.compressed).toBe(false);
                expect(kp.network).toBe(networks.testnet);
            });

            fixtures.invalid.fromPublicKey.forEach((f) => {
                it(`throws ${f.exception}`, () => {
                    const Q = f.Q ? h(f.Q) : new Uint8Array(0);
                    expect(() =>
                        ECPairSigner.fromPublicKey(backend, Q as PublicKey, networks.bitcoin),
                    ).toThrow(new RegExp(f.exception));
                });
            });
        });

        describe('fromWIF', () => {
            fixtures.valid.forEach((f) => {
                it(`imports ${f.WIF} (${f.network})`, () => {
                    const network = defined(
                        (networks as Record<string, typeof networks.bitcoin>)[f.network],
                    );
                    const kp = ECPairSigner.fromWIF(backend, f.WIF, network);

                    expect(toHex(defined(kp.privateKey))).toBe(f.d);
                    expect(kp.compressed).toBe(f.compressed);
                    expect(kp.network).toBe(network);
                });
            });

            fixtures.valid.forEach((f) => {
                it(`imports ${f.WIF} (via network list)`, () => {
                    const kp = ECPairSigner.fromWIF(backend, f.WIF, NETWORKS_LIST);
                    expect(toHex(defined(kp.privateKey))).toBe(f.d);
                    expect(kp.compressed).toBe(f.compressed);
                    expect(kp.network).toBe(
                        (networks as Record<string, typeof networks.bitcoin>)[f.network],
                    );
                });
            });

            fixtures.invalid.fromWIF.forEach((f) => {
                it(`throws on ${f.WIF}`, () => {
                    expect(() => {
                        const net = (f as { network?: string }).network
                            ? defined(
                                  (networks as Record<string, typeof networks.bitcoin>)[
                                      (f as { network: string }).network
                                  ],
                              )
                            : NETWORKS_LIST;
                        ECPairSigner.fromWIF(backend, f.WIF, net);
                    }).toThrow(new RegExp(f.exception));
                });
            });
        });

        describe('toWIF', () => {
            fixtures.valid.forEach((f) => {
                it(`exports ${f.WIF}`, () => {
                    const kp = ECPairSigner.fromWIF(backend, f.WIF, NETWORKS_LIST);
                    expect(kp.toWIF()).toBe(f.WIF);
                });
            });

            it('throws if no private key (public-key-only signer)', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(() => kp.toWIF()).toThrow(/Missing private key/);
            });
        });

        describe('makeRandom', () => {
            it('generates a valid ECPairSigner', () => {
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin);
                expect(kp.compressed).toBe(true);
                expect(kp.network).toBe(networks.bitcoin);
                expect(kp.privateKey).toBeDefined();
                expect(kp.publicKey.length).toBe(33);
            });

            it('allows custom rng', () => {
                const seed = new Uint8Array(48).fill(4);
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin, {
                    rng: () => seed,
                });
                expect(kp.privateKey).toBeDefined();
                expect(defined(kp.privateKey).length).toBe(32);
                expect(backend.isPrivate(defined(kp.privateKey))).toBe(true);
            });

            it('produces deterministic output from fixed seed', () => {
                const seed = new Uint8Array(48).fill(4);
                const kp1 = ECPairSigner.makeRandom(backend, networks.bitcoin, { rng: () => seed });
                const kp2 = ECPairSigner.makeRandom(backend, networks.bitcoin, { rng: () => seed });
                expect(bytesEqual(defined(kp1.privateKey), defined(kp2.privateKey))).toBe(true);
            });

            it('supports options', () => {
                const kp = ECPairSigner.makeRandom(backend, networks.testnet, {
                    compressed: false,
                });
                expect(kp.compressed).toBe(false);
                expect(kp.network).toBe(networks.testnet);
            });

            it('throws if rng returns bad length', () => {
                expect(() =>
                    ECPairSigner.makeRandom(backend, networks.bitcoin, {
                        rng: () => new Uint8Array(28),
                    }),
                ).toThrow(/Expected 48 bytes from rng, got 28/);
            });

            it('reduces 48-byte all-zeros seed to private key 1', () => {
                // 0 mod (n-1) + 1 = 1
                const seed = new Uint8Array(48);
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin, { rng: () => seed });
                expect(bytesEqual(defined(kp.privateKey), ONE)).toBe(true);
            });

            it('reduces 48-byte seed via FIPS mod (n-1) + 1', () => {
                // If seed encodes exactly n-1 as a 48-byte big-endian:
                // (n-1) mod (n-1) + 1 = 0 + 1 = 1
                const nMinus1Padded = new Uint8Array(48);
                nMinus1Padded.set(GROUP_ORDER_LESS_1, 48 - 32);
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin, {
                    rng: () => nMinus1Padded,
                });
                expect(bytesEqual(defined(kp.privateKey), ONE)).toBe(true);
            });

            it('never produces zero from any seed', () => {
                // Verify the +1 offset prevents zero: seed=0 → key=1
                const seed = new Uint8Array(48);
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin, { rng: () => seed });
                expect(isPrivateKey(defined(kp.privateKey))).toBe(true);
            });

            it('uses crypto.getRandomValues as default rng', () => {
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin);
                expect(kp.privateKey).toBeDefined();
            });
        });

        describe('publicKey', () => {
            it('lazily derives public key from private key', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(toHex(kp.publicKey)).toBe(
                    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                );
            });

            it('returns pre-set public key for public-only signer', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(toHex(kp.publicKey)).toBe(toHex(pub));
            });

            it('returns uncompressed key when compressed=false', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                    { compressed: false },
                );
                expect(kp.publicKey.length).toBe(65);
                expect(kp.publicKey[0]).toBe(0x04);
            });
        });

        describe('xOnlyPublicKey', () => {
            it('returns 32-byte x-only key', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.xOnlyPublicKey.length).toBe(32);
                // x-only is the public key without prefix byte
                expect(toHex(kp.xOnlyPublicKey)).toBe(
                    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                );
            });

            it('is memoized', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                const first = kp.xOnlyPublicKey;
                const second = kp.xOnlyPublicKey;
                expect(first).toBe(second);
            });
        });

        describe('capabilities', () => {
            it('private key signer has full capabilities', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.hasCapability(SignerCapability.EcdsaSign)).toBe(true);
                expect(kp.hasCapability(SignerCapability.EcdsaVerify)).toBe(true);
                expect(kp.hasCapability(SignerCapability.PrivateKeyExport)).toBe(true);
                expect(kp.hasCapability(SignerCapability.PublicKeyTweak)).toBe(true);
                expect(kp.hasCapability(SignerCapability.SchnorrSign)).toBe(true);
                expect(kp.hasCapability(SignerCapability.SchnorrVerify)).toBe(true);
            });

            it('capabilities is a bitmask number', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(typeof kp.capabilities).toBe('number');
            });

            it('public-key-only signer has limited capabilities', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(kp.hasCapability(SignerCapability.EcdsaSign)).toBe(false);
                expect(kp.hasCapability(SignerCapability.EcdsaVerify)).toBe(true);
                expect(kp.hasCapability(SignerCapability.PrivateKeyExport)).toBe(false);
                expect(kp.hasCapability(SignerCapability.SchnorrSign)).toBe(false);
            });

            it('capabilities are memoized', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                const first = kp.capabilities;
                const second = kp.capabilities;
                expect(first).toBe(second);
            });

            it('no SchnorrSign without backend signSchnorr', () => {
                const backendNoSchnorr = mockBackend(backend, {
                    signSchnorr: undefined,
                });
                const kp = ECPairSigner.fromPrivateKey(
                    backendNoSchnorr,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.hasCapability(SignerCapability.SchnorrSign)).toBe(false);
            });

            it('no SchnorrVerify without backend verifySchnorr', () => {
                const backendNoSchnorr = mockBackend(backend, {
                    verifySchnorr: undefined,
                });
                const kp = ECPairSigner.fromPrivateKey(
                    backendNoSchnorr,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.hasCapability(SignerCapability.SchnorrVerify)).toBe(false);
            });

            it('HdDerivation is not set', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.hasCapability(SignerCapability.HdDerivation)).toBe(false);
            });
        });

        describe('sign', () => {
            const privKey = createPrivateKey(ONE);
            const msgHash = createMessageHash(ZERO);

            it('signs a message', () => {
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const sig = kp.sign(msgHash);
                expect(sig.length).toBe(64);
            });

            it('sign with lowR=false is same as default', () => {
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const sigDefault = kp.sign(msgHash);
                const sigFalse = kp.sign(msgHash, false);
                expect(bytesEqual(sigDefault, sigFalse)).toBe(true);
            });

            it('sign with lowR=true produces low-R signature', () => {
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const sig = kp.sign(msgHash, true);
                // First byte of R should be <= 0x7f
                expect(defined(sig[0]) <= 0x7f).toBe(true);
            });

            it('throws if no private key', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(() => kp.sign(msgHash)).toThrow(/Missing private key/);
            });
        });

        describe('signSchnorr', () => {
            const privKey = createPrivateKey(ONE);
            const msgHash = createMessageHash(new Uint8Array(32).fill(2));

            it('produces Schnorr signature', () => {
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const sig = kp.signSchnorr(msgHash);
                expect(sig.length).toBe(64);
            });

            it('throws if no private key', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(() => kp.signSchnorr(msgHash)).toThrow(/Missing private key/);
            });

            it('throws if backend has no signSchnorr', () => {
                const backendNoSchnorr = mockBackend(backend, {
                    signSchnorr: undefined,
                });
                const kp = ECPairSigner.fromPrivateKey(
                    backendNoSchnorr,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(() => kp.signSchnorr(msgHash)).toThrow(/signSchnorr not supported/);
            });
        });

        describe('verify', () => {
            it('verifies valid ECDSA signature', () => {
                const privKey = createPrivateKey(ONE);
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const msgHash = createMessageHash(ZERO);
                const sig = kp.sign(msgHash);
                expect(kp.verify(msgHash, sig)).toBe(true);
            });

            it('rejects invalid signature', () => {
                const privKey = createPrivateKey(ONE);
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const msgHash = createMessageHash(ZERO);
                const badSig = createSignature(new Uint8Array(64).fill(1));
                expect(kp.verify(msgHash, badSig)).toBe(false);
            });
        });

        describe('verifySchnorr', () => {
            it('verifies valid Schnorr signature', () => {
                const privKey = createPrivateKey(ONE);
                const kp = ECPairSigner.fromPrivateKey(backend, privKey, networks.bitcoin);
                const msgHash = createMessageHash(new Uint8Array(32).fill(2));
                const sig = kp.signSchnorr(msgHash);
                expect(kp.verifySchnorr(msgHash, sig)).toBe(true);
            });

            it('throws if backend has no verifySchnorr', () => {
                const backendNoSchnorr = mockBackend(backend, {
                    verifySchnorr: undefined,
                });
                const kp = ECPairSigner.fromPrivateKey(
                    backendNoSchnorr,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                const msgHash = createMessageHash(ZERO);
                const fakeSig = createSchnorrSignature(new Uint8Array(64));
                expect(() => kp.verifySchnorr(msgHash, fakeSig)).toThrow(
                    /verifySchnorr not supported/,
                );
            });
        });

        describe('tweak', () => {
            fixtures.valid.forEach((f) => {
                it(`tweaks private and public key for ${f.WIF}`, () => {
                    const kp = ECPairSigner.fromWIF(backend, f.WIF, NETWORKS_LIST);
                    const tweakHash = tapTweakHash(kp.publicKey.subarray(1, 33));

                    const tweakedKp = kp.tweak(tweakHash as Bytes32);
                    expect(tweakedKp.toWIF()).toBe(f.tweak);

                    // Also tweak from public key and compare
                    const network = defined(
                        (networks as Record<string, typeof networks.bitcoin>)[f.network],
                    );
                    const pubOnlyKp = ECPairSigner.fromPublicKey(
                        backend,
                        createPublicKey(h(f.Q)),
                        network,
                        { compressed: f.compressed },
                    );
                    const tweakedPubOnly = pubOnlyKp.tweak(tweakHash as Bytes32);
                    expect(bytesEqual(tweakedKp.publicKey, tweakedPubOnly.publicKey)).toBe(true);
                });
            });

            it('tweak from public key produces valid signer', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                const tweakHash = tapTweakHash(pub.subarray(1, 33));
                const tweaked = kp.tweak(tweakHash as Bytes32);
                expect(tweaked.publicKey.length).toBe(33);
                expect(tweaked.privateKey).toBeUndefined();
            });
        });

        describe('privateKey', () => {
            it('returns private key for key-pair signer', () => {
                const kp = ECPairSigner.fromPrivateKey(
                    backend,
                    createPrivateKey(ONE),
                    networks.bitcoin,
                );
                expect(kp.privateKey).toBeDefined();
                expect(bytesEqual(defined(kp.privateKey), ONE)).toBe(true);
            });

            it('returns undefined for public-only signer', () => {
                const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
                const kp = ECPairSigner.fromPublicKey(
                    backend,
                    createPublicKey(pub),
                    networks.bitcoin,
                );
                expect(kp.privateKey).toBeUndefined();
            });
        });

        describe('sign and verify round-trip', () => {
            it('ECDSA sign/verify round-trip', () => {
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin);
                const msgHash = createMessageHash(sha256(ONE));
                const sig = kp.sign(msgHash);
                expect(kp.verify(msgHash, sig)).toBe(true);
            });

            it('Schnorr sign/verify round-trip', () => {
                const kp = ECPairSigner.makeRandom(backend, networks.bitcoin);
                const msgHash = createMessageHash(sha256(ONE));
                const sig = kp.signSchnorr(msgHash);
                expect(kp.verifySchnorr(msgHash, sig)).toBe(true);
            });
        });
    });
}

// ---------------------------------------------------------------------------
// 9. ECPairSigner — backend-specific tests
// ---------------------------------------------------------------------------

describe('ECPairSigner [LegacyBackend specific]', () => {
    const backend = createLegacyBackend(tinysecp as unknown as TinySecp256k1Interface);

    describe('optional low R signing', () => {
        const sig = h(
            '95a6619140fca3366f1d3b013b0367c4f86e39508a50fdce' +
                'e5245fbb8bd60aa6086449e28cf15387cf9f85100bfd0838624ca96759e59f65c10a00' +
                '16b86f5229',
        );
        const sigLowR = h(
            '6a2660c226e8055afad317eeba918a304be79208d505' +
                '3bc5ea4a5e4c5892b4a061c717c5284ae5202d721c0e49b4717b79966280906b1d3b52' +
                '95d1fdde963c35',
        );
        const lowRKeyPair = ECPairSigner.fromWIF(
            backend,
            'L3nThUzbAwpUiBAjR5zCu66ybXSPMr2zZ3ikp' + 'ScpTPiYTxBynfZu',
            networks.bitcoin,
        );
        const dataToSign = createMessageHash(
            h('b6c5c548a7f6164c8aa7af5350901626ebd69f9ae' + '2c1ecf8871f5088ec204cfe'),
        );

        it('signs with normal R by default', () => {
            const signed = lowRKeyPair.sign(dataToSign);
            expect(bytesEqual(signed, sig)).toBe(true);
        });

        it('signs with low R when true is passed', () => {
            const signed = lowRKeyPair.sign(dataToSign, true);
            expect(bytesEqual(signed, sigLowR)).toBe(true);
        });
    });

    describe('Schnorr test vectors', () => {
        it('creates correct Schnorr signature', () => {
            const kp = ECPairSigner.fromPrivateKey(
                backend,
                createPrivateKey(ONE),
                networks.bitcoin,
                { compressed: false },
            );
            const msgHash = createMessageHash(new Uint8Array(32).fill(2));
            const expected =
                'cde43b67d4326fa6ff1b40711615b692a997e193cc512f3a40e5cd4a5c9be18ca871296fa967f4dc13634c70d965223d637546a0b519050bae82c76d3ae627ff';
            expect(toHex(kp.signSchnorr(msgHash))).toBe(expected);
        });

        it('verifies Schnorr signature', () => {
            const kp = ECPairSigner.fromPrivateKey(
                backend,
                createPrivateKey(ONE),
                networks.bitcoin,
                { compressed: false },
            );
            const msgHash = createMessageHash(new Uint8Array(32).fill(2));
            const schnorrsig = h(
                '4bc68cbd7c0b769b2dff262e9971756da7ab78402ed6f710c3788ce815e9c06a011bab7a527e33c6a1df0dad5ed05a04b8f3be656d8578502fef07f8215d37db',
            );
            expect(kp.verifySchnorr(msgHash, schnorrsig as SchnorrSignature)).toBe(true);
        });
    });
});

// ---------------------------------------------------------------------------
// 10. Edge cases and coverage gaps
// ---------------------------------------------------------------------------

describe('ECPairSigner edge cases', () => {
    const noble = createNobleBackend();

    it('tweak with odd-Y public key (prefix 03)', () => {
        // n-1 has a compressed key with prefix 03
        const kp = ECPairSigner.fromPrivateKey(
            noble,
            createPrivateKey(GROUP_ORDER_LESS_1),
            networks.bitcoin,
        );
        expect(kp.publicKey[0]).toBe(0x03);

        const tweakHash = tapTweakHash(kp.publicKey.subarray(1, 33));
        const tweaked = kp.tweak(tweakHash as Bytes32);
        expect(tweaked.publicKey.length).toBe(33);
    });

    it('tweak with odd-Y uncompressed key (prefix 04, odd last byte)', () => {
        // Find a key that produces uncompressed pubkey with odd Y
        const kp = ECPairSigner.fromPrivateKey(
            noble,
            createPrivateKey(GROUP_ORDER_LESS_1),
            networks.bitcoin,
            { compressed: false },
        );
        expect(kp.publicKey[0]).toBe(0x04);
        const yLastByte = defined(kp.publicKey[64]);
        // This key should have odd Y (since compressed form is 03)
        expect(yLastByte & 1).toBe(1);

        const tweakHash = tapTweakHash(kp.publicKey.subarray(1, 33));
        const tweaked = kp.tweak(tweakHash as Bytes32);
        expect(tweaked.publicKey.length).toBe(65);
    });

    it('publicKey getter derives from private key (not from public)', () => {
        // pointFromScalar returns null mock to test the error path
        const brokenBackend = mockBackend(noble, {
            isPrivate: () => true,
            pointFromScalar: () => null,
        });
        const kp = ECPairSigner.fromPrivateKey(
            brokenBackend,
            createPrivateKey(ONE),
            networks.bitcoin,
        );
        expect(() => kp.publicKey).toThrow('Failed to derive public key from private key');
    });

    it('tweak from public key throws on null result', () => {
        const brokenBackend = mockBackend(noble, {
            xOnlyPointAddTweak: () => null,
        });
        const pub = h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
        const kp = ECPairSigner.fromPublicKey(
            brokenBackend,
            createPublicKey(pub),
            networks.bitcoin,
        );
        expect(() => kp.tweak(ONE as Bytes32)).toThrow('Cannot tweak public key');
    });

    it('tweak from private key throws on null result', () => {
        const brokenBackend = mockBackend(noble, {
            privateAdd: () => null,
        });
        const kp = ECPairSigner.fromPrivateKey(
            brokenBackend,
            createPrivateKey(ONE),
            networks.bitcoin,
        );
        expect(() => kp.tweak(ONE as Bytes32)).toThrow('Invalid tweaked private key');
    });

    it('makeRandom uses crypto.getRandomValues as default rng', () => {
        const kp = ECPairSigner.makeRandom(noble, networks.bitcoin);
        expect(kp.privateKey).toBeDefined();
        expect(kp.publicKey.length).toBe(33);
    });

    it('xOnlyPublicKey works for 32-byte input (passthrough)', () => {
        // The toXOnly function checks if length is 32, returning as-is
        // This is tested indirectly via xOnlyPublicKey getter on compressed keys
        const kp = ECPairSigner.fromPrivateKey(noble, createPrivateKey(ONE), networks.bitcoin);
        const xOnly = kp.xOnlyPublicKey;
        // xOnly should be the pubkey minus prefix byte
        expect(xOnly.length).toBe(32);
    });
});
