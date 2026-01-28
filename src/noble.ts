import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { mod } from '@noble/curves/abstract/modular.js';
import type { CryptoBackend, Parity, XOnlyPointAddTweakResult } from './backend.js';
import type {
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';
import { toHex } from './types.js';

const Point = secp256k1.Point;
const N = Point.Fn.ORDER;

function bigintToBytes32(n: bigint): Uint8Array {
    const hex = n.toString(16).padStart(64, '0');
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i] as number);
    }
    return result;
}

/**
 * {@link CryptoBackend} implementation backed by `@noble/curves/secp256k1`.
 *
 * Pure JavaScript, no native dependencies.
 *
 * Prefer {@link createNobleBackend} for construction.
 */
export class NobleBackend implements CryptoBackend {
    /** @inheritDoc */
    public isPrivate(d: Uint8Array): boolean {
        return secp256k1.utils.isValidSecretKey(d);
    }

    /** @inheritDoc */
    public isPoint(p: Uint8Array): boolean {
        try {
            Point.fromHex(toHex(p));
            return true;
        } catch {
            return false;
        }
    }

    /** @inheritDoc */
    public pointFromScalar(d: PrivateKey, compressed?: boolean): PublicKey | null {
        try {
            return secp256k1.getPublicKey(d, compressed ?? true) as PublicKey;
        } catch {
            return null;
        }
    }

    /** @inheritDoc */
    public pointCompress(p: PublicKey, compressed?: boolean): PublicKey {
        const point = Point.fromHex(toHex(p));
        return point.toBytes(compressed ?? true) as PublicKey;
    }

    /** @inheritDoc */
    public pointAddScalar(p: PublicKey, tweak: Bytes32, compressed?: boolean): PublicKey | null {
        try {
            const point = Point.fromHex(toHex(p));
            const tweakBigint = bytesToBigInt(tweak);
            if (tweakBigint === 0n) {
                return point.toBytes(compressed ?? true) as PublicKey;
            }
            const tweakPub = secp256k1.getPublicKey(tweak, true);
            const tweakPoint = Point.fromHex(toHex(tweakPub));
            const result = point.add(tweakPoint);
            return result.toBytes(compressed ?? true) as PublicKey;
        } catch {
            return null;
        }
    }

    /** @inheritDoc */
    public xOnlyPointAddTweak(p: XOnlyPublicKey, tweak: Bytes32): XOnlyPointAddTweakResult | null {
        try {
            const point = schnorr.utils.lift_x(bytesToBigInt(p));
            const tweakBigint = bytesToBigInt(tweak);
            if (tweakBigint >= N) return null;
            const tweakPub = secp256k1.getPublicKey(tweak, true);
            const tweakPoint = Point.fromHex(toHex(tweakPub));
            const result = point.add(tweakPoint);
            const xBytes = schnorr.utils.pointToBytes(result);
            const parity = Number(result.y & 1n) as Parity;
            return {
                parity,
                xOnlyPubkey: xBytes as XOnlyPublicKey,
            };
        } catch {
            return null;
        }
    }

    /** @inheritDoc */
    public privateAdd(d: PrivateKey, tweak: Bytes32): PrivateKey | null {
        const dBigint = bytesToBigInt(d);
        const tweakBigint = bytesToBigInt(tweak);
        const result = mod(dBigint + tweakBigint, N);
        if (result === 0n) return null;
        return bigintToBytes32(result) as PrivateKey;
    }

    /** @inheritDoc */
    public privateNegate(d: PrivateKey): PrivateKey {
        const dBigint = bytesToBigInt(d);
        const result = mod(N - dBigint, N);
        return bigintToBytes32(result) as PrivateKey;
    }

    /** @inheritDoc */
    public sign(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): Signature {
        return secp256k1.sign(hash, privateKey, {
            prehash: false,
            lowS: true,
            extraEntropy: extraEntropy ?? false,
        }) as Signature;
    }

    /** @inheritDoc */
    public verify(hash: MessageHash, publicKey: PublicKey, signature: Signature): boolean {
        return secp256k1.verify(signature, hash, publicKey, {
            prehash: false,
            lowS: true,
        });
    }

    /** @inheritDoc */
    public signSchnorr(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): SchnorrSignature {
        return schnorr.sign(hash, privateKey, extraEntropy) as SchnorrSignature;
    }

    /** @inheritDoc */
    public verifySchnorr(hash: MessageHash, publicKey: XOnlyPublicKey, signature: SchnorrSignature): boolean {
        return schnorr.verify(signature, hash, publicKey);
    }
}

/**
 * Creates a {@link NobleBackend} instance.
 *
 * @returns A new pure-JS secp256k1 backend powered by `@noble/curves`.
 */
export function createNobleBackend(): NobleBackend {
    return new NobleBackend();
}
