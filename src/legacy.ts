import type { CryptoBackend, XOnlyPointAddTweakResult } from './backend.js';
import type {
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';

/**
 * Subset of the `tiny-secp256k1` API consumed by {@link LegacyBackend}.
 *
 * Pass an object satisfying this interface to {@link createLegacyBackend}
 * to bridge an existing `tiny-secp256k1` installation into the
 * {@link CryptoBackend} contract.
 */
export interface TinySecp256k1Interface {
    /** @see {@link CryptoBackend.isPoint} */
    isPoint(p: Uint8Array): boolean;
    /** @see {@link CryptoBackend.pointCompress} */
    pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
    /** @see {@link CryptoBackend.isPrivate} */
    isPrivate(d: Uint8Array): boolean;
    /** @see {@link CryptoBackend.pointFromScalar} */
    pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null;
    /** @see {@link CryptoBackend.pointAddScalar} */
    pointAddScalar?(p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null;
    /** @see {@link CryptoBackend.xOnlyPointAddTweak} */
    xOnlyPointAddTweak(
        p: Uint8Array,
        tweak: Uint8Array,
    ): { parity: 1 | 0; xOnlyPubkey: Uint8Array } | null;
    /** @see {@link CryptoBackend.privateAdd} */
    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    /** @see {@link CryptoBackend.privateNegate} */
    privateNegate(d: Uint8Array): Uint8Array;
    /** @see {@link CryptoBackend.sign} */
    sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    /** @see {@link CryptoBackend.signSchnorr} */
    signSchnorr?(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    /** @see {@link CryptoBackend.verify} */
    verify(h: Uint8Array, Q: Uint8Array, signature: Uint8Array, strict?: boolean): boolean;
    /** @see {@link CryptoBackend.verifySchnorr} */
    verifySchnorr?(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
}

/**
 * {@link CryptoBackend} adapter that delegates to a `tiny-secp256k1`
 * compatible library.
 *
 * Prefer {@link createLegacyBackend} for construction.
 */
export class LegacyBackend implements CryptoBackend {
    readonly #ecc: TinySecp256k1Interface;

    /**
     * @param ecc - Object implementing the {@link TinySecp256k1Interface}.
     */
    public constructor(ecc: TinySecp256k1Interface) {
        this.#ecc = ecc;
    }

    /** `true` when the underlying library supports Schnorr signing. */
    public get hasSchnorrSign(): boolean {
        return typeof this.#ecc.signSchnorr === 'function';
    }

    /** `true` when the underlying library supports Schnorr verification. */
    public get hasSchnorrVerify(): boolean {
        return typeof this.#ecc.verifySchnorr === 'function';
    }

    /** @inheritDoc */
    public isPrivate(d: Uint8Array): boolean {
        return this.#ecc.isPrivate(d);
    }

    /** @inheritDoc */
    public isPoint(p: Uint8Array): boolean {
        return this.#ecc.isPoint(p);
    }

    /** @inheritDoc */
    public pointFromScalar(d: PrivateKey, compressed?: boolean): PublicKey | null {
        return this.#ecc.pointFromScalar(d, compressed) as PublicKey | null;
    }

    /** @inheritDoc */
    public pointCompress(p: PublicKey, compressed?: boolean): PublicKey {
        return this.#ecc.pointCompress(p, compressed) as PublicKey;
    }

    /** @inheritDoc */
    public pointAddScalar(p: PublicKey, tweak: Bytes32, compressed?: boolean): PublicKey | null {
        if (!this.#ecc.pointAddScalar) {
            throw new Error('pointAddScalar not supported by ecc library');
        }
        return this.#ecc.pointAddScalar(p, tweak, compressed) as PublicKey | null;
    }

    /** @inheritDoc */
    public xOnlyPointAddTweak(p: XOnlyPublicKey, tweak: Bytes32): XOnlyPointAddTweakResult | null {
        const result = this.#ecc.xOnlyPointAddTweak(p, tweak);
        if (result === null) return null;
        return {
            parity: result.parity,
            xOnlyPubkey: result.xOnlyPubkey as XOnlyPublicKey,
        };
    }

    /** @inheritDoc */
    public privateAdd(d: PrivateKey, tweak: Bytes32): PrivateKey | null {
        return this.#ecc.privateAdd(d, tweak) as PrivateKey | null;
    }

    /** @inheritDoc */
    public privateNegate(d: PrivateKey): PrivateKey {
        return this.#ecc.privateNegate(d) as PrivateKey;
    }

    /** @inheritDoc */
    public sign(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): Signature {
        return this.#ecc.sign(hash, privateKey, extraEntropy) as Signature;
    }

    /** @inheritDoc */
    public verify(hash: MessageHash, publicKey: PublicKey, signature: Signature): boolean {
        return this.#ecc.verify(hash, publicKey, signature);
    }

    /**
     * @inheritDoc
     * @throws If the underlying `tiny-secp256k1` library lacks `signSchnorr`.
     */
    public signSchnorr(
        hash: MessageHash,
        privateKey: PrivateKey,
        extraEntropy?: Uint8Array,
    ): SchnorrSignature {
        if (!this.#ecc.signSchnorr) {
            throw new Error('signSchnorr not supported by ecc library');
        }
        return this.#ecc.signSchnorr(hash, privateKey, extraEntropy) as SchnorrSignature;
    }

    /**
     * @inheritDoc
     * @throws If the underlying `tiny-secp256k1` library lacks `verifySchnorr`.
     */
    public verifySchnorr(
        hash: MessageHash,
        publicKey: XOnlyPublicKey,
        signature: SchnorrSignature,
    ): boolean {
        if (!this.#ecc.verifySchnorr) {
            throw new Error('verifySchnorr not supported by ecc library');
        }
        return this.#ecc.verifySchnorr(hash, publicKey, signature);
    }
}

/**
 * Creates a {@link LegacyBackend} wrapping a `tiny-secp256k1` compatible object.
 *
 * @param ecc - Object satisfying the {@link TinySecp256k1Interface}.
 */
export function createLegacyBackend(ecc: TinySecp256k1Interface): LegacyBackend {
    return new LegacyBackend(ecc);
}
