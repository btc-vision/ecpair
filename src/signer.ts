import type { CryptoBackend } from './backend.js';
import type {
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';
import { SignerCapability } from './capability.js';
import type { Network } from './networks.js';
import { assertBytes32, createPrivateKey, createPublicKey, createXOnlyPublicKey, concatBytes } from './types.js';
import { encodeWIF, decodeWIF } from './wif.js';

/**
 * Minimal synchronous signer interface.
 *
 * Consumers that only need ECDSA signing can depend on this rather than the
 * full {@link UniversalSigner}.
 */
export interface Signer {
    /** SEC1-encoded public key (33 or 65 bytes). */
    readonly publicKey: PublicKey;
    /** Network this signer is bound to, if any. */
    readonly network?: Network | undefined;
    /**
     * Produces a compact ECDSA signature over `hash`.
     * @param hash - 32-byte message digest.
     * @param lowR - When `true`, grinds for a low-R value (smaller DER encoding).
     */
    sign(hash: MessageHash, lowR?: boolean): Signature;
    /**
     * Produces a BIP-340 Schnorr signature over `hash`.
     * @param hash - 32-byte message digest.
     */
    signSchnorr?(hash: MessageHash): SchnorrSignature;
}

/**
 * Asynchronous counterpart of {@link Signer} for hardware wallets or
 * remote signing services.
 */
export interface SignerAsync {
    /** SEC1-encoded public key (33 or 65 bytes). */
    readonly publicKey: PublicKey;
    /** Network this signer is bound to, if any. */
    readonly network?: Network | undefined;
    /**
     * Produces a compact ECDSA signature over `hash`.
     * @param hash - 32-byte message digest.
     * @param lowR - When `true`, grinds for a low-R value.
     */
    sign(hash: MessageHash, lowR?: boolean): Promise<Signature>;
    /**
     * Produces a BIP-340 Schnorr signature over `hash`.
     * @param hash - 32-byte message digest.
     */
    signSchnorr?(hash: MessageHash): Promise<SchnorrSignature>;
}

/**
 * Full-featured signer interface exposing every operation that
 * {@link ECPairSigner} supports.
 */
export interface UniversalSigner extends Signer {
    /** 32-byte BIP-340 x-only public key. */
    readonly xOnlyPublicKey: XOnlyPublicKey;
    /** Network this signer is bound to. */
    readonly network: Network;
    /** Whether the public key is in compressed SEC1 form. */
    readonly compressed: boolean;
    /** Bitmask of {@link SignerCapability} flags. */
    readonly capabilities: number;
    /** Raw private key bytes, or `undefined` for public-key-only signers. */
    readonly privateKey?: PrivateKey | undefined;
    /**
     * Tests whether the signer has a specific capability.
     * @param cap - {@link SignerCapability} flag to test.
     */
    hasCapability(cap: SignerCapability): boolean;
    /**
     * Verifies a compact ECDSA signature.
     * @param hash - 32-byte message digest.
     * @param signature - Compact ECDSA signature.
     */
    verify(hash: MessageHash, signature: Signature): boolean;
    /**
     * Verifies a BIP-340 Schnorr signature.
     * @param hash - 32-byte message digest.
     * @param signature - 64-byte Schnorr signature.
     */
    verifySchnorr(hash: MessageHash, signature: SchnorrSignature): boolean;
    /**
     * Derives a new signer by applying a Taproot-style scalar tweak.
     * @param t - 32-byte tweak scalar.
     */
    tweak(t: Bytes32): UniversalSigner;
    /**
     * Exports the private key as a WIF string.
     * @throws If this is a public-key-only signer.
     */
    toWIF(): string;
}

/**
 * Options shared by all {@link ECPairSigner} factory methods.
 */
export interface SignerOptions {
    /**
     * Whether to use compressed SEC1 encoding for the public key.
     * Defaults to `true`.
     */
    readonly compressed?: boolean | undefined;
}

/**
 * Options for {@link ECPairSigner.makeRandom}, extending {@link SignerOptions}
 * with an optional custom RNG.
 */
export interface RandomSignerOptions extends SignerOptions {
    /**
     * Custom random-byte generator.  Must return exactly `size` bytes.
     * Falls back to `crypto.getRandomValues` when omitted.
     */
    readonly rng?: ((size: number) => Uint8Array) | undefined;
}

/**
 * Returns `true` when the SEC1 public key has an odd Y coordinate.
 *
 * Handles compressed (prefix `0x03`) and uncompressed (prefix `0x04`,
 * 65 bytes, last byte odd) encodings.
 */
function hasOddY(pubKey: PublicKey): boolean {
    if (pubKey[0] === 0x03) return true;
    if (pubKey[0] === 0x04 && pubKey.length === 65) {
        return ((pubKey[64] as number) & 1) === 1;
    }
    return false;
}

/**
 * Extracts the 32-byte x-only public key from a SEC1-encoded key and
 * returns it as a validated {@link XOnlyPublicKey}.
 *
 * @param pubKey - Compressed (33 bytes) or x-only (32 bytes) public key.
 * @returns Branded 32-byte x-only public key.
 */
function toXOnly(pubKey: Uint8Array): XOnlyPublicKey {
    const raw = pubKey.length === 32 ? pubKey : pubKey.subarray(1, 33);
    return createXOnlyPublicKey(raw);
}

/**
 * Concrete secp256k1 key-pair signer backed by a {@link CryptoBackend}.
 *
 * Instances are created exclusively through the static factory methods
 * ({@link ECPairSigner.fromPrivateKey}, {@link ECPairSigner.fromPublicKey},
 * {@link ECPairSigner.fromWIF}, {@link ECPairSigner.makeRandom}).
 *
 * @example
 * ```ts
 * import { ECPairSigner, createNobleBackend } from 'ecpair';
 *
 * const backend = createNobleBackend();
 * const signer  = ECPairSigner.makeRandom(backend, bitcoin);
 * const sig     = signer.sign(messageHash);
 * ```
 */
export class ECPairSigner implements UniversalSigner {
    readonly #backend: CryptoBackend;
    readonly #privateKey: PrivateKey | undefined;
    readonly #network: Network;
    readonly #compressed: boolean;
    #publicKey: PublicKey | undefined;
    #xOnlyPublicKey: XOnlyPublicKey | undefined;
    #capabilities: number | undefined;

    private constructor(
        backend: CryptoBackend,
        privateKey: PrivateKey,
        publicKey: undefined,
        network: Network,
        options?: SignerOptions,
    );
    private constructor(
        backend: CryptoBackend,
        privateKey: undefined,
        publicKey: PublicKey,
        network: Network,
        options?: SignerOptions,
    );
    private constructor(
        backend: CryptoBackend,
        privateKey: PrivateKey | undefined,
        publicKey: PublicKey | undefined,
        network: Network,
        options?: SignerOptions,
    ) {
        if (options?.compressed !== undefined && typeof options.compressed !== 'boolean') {
            throw new TypeError(
                `Expected boolean for compressed, got ${typeof options.compressed}`,
            );
        }

        this.#backend = backend;
        this.#privateKey = privateKey;
        this.#compressed = options?.compressed ?? true;
        this.#network = network;

        if (publicKey !== undefined) {
            this.#publicKey = backend.pointCompress(publicKey, this.#compressed);
        }
    }

    /**
     * Creates a signer from a raw private key.
     *
     * @param backend - Cryptographic backend to use.
     * @param privateKey - 32-byte secp256k1 private key.
     * @param network - Target network.
     * @param options - Optional settings (e.g. compressed).
     * @throws {TypeError} If the private key is not in the valid range `[1, n)`.
     */
    public static fromPrivateKey(
        backend: CryptoBackend,
        privateKey: PrivateKey,
        network: Network,
        options?: SignerOptions,
    ): ECPairSigner {
        if (!backend.isPrivate(privateKey)) {
            throw new TypeError('Private key not in range [1, n)');
        }
        return new ECPairSigner(backend, privateKey, undefined, network, options);
    }

    /**
     * Creates a public-key-only signer (cannot sign, export WIF, etc.).
     *
     * @param backend - Cryptographic backend to use.
     * @param publicKey - SEC1-encoded public key.
     * @param network - Target network.
     * @param options - Optional settings (e.g. compressed).
     * @throws If the public key is not a valid curve point.
     */
    public static fromPublicKey(
        backend: CryptoBackend,
        publicKey: PublicKey,
        network: Network,
        options?: SignerOptions,
    ): ECPairSigner {
        if (!backend.isPoint(publicKey)) {
            throw new Error('Point not on the curve');
        }
        return new ECPairSigner(backend, undefined, publicKey, network, options);
    }

    /**
     * Imports a signer from a WIF-encoded private key string.
     *
     * @param backend - Cryptographic backend to use.
     * @param wifString - Base58Check WIF string.
     * @param network - One or more candidate networks whose WIF version byte is matched.
     * @throws If no network matches the decoded version byte.
     */
    public static fromWIF(
        backend: CryptoBackend,
        wifString: string,
        network: Network | readonly Network[],
    ): ECPairSigner {
        const decoded = decodeWIF(wifString, network);
        return ECPairSigner.fromPrivateKey(backend, decoded.privateKey, decoded.network, {
            compressed: decoded.compressed,
        });
    }

    /**
     * Generates a new signer with a random private key.
     *
     * Uses `backend.generatePrivateKey()` when available, otherwise
     * `crypto.getRandomValues`, unless a custom `rng` is provided.
     *
     * @param backend - Cryptographic backend to use.
     * @param network - Target network.
     * @param options - Optional settings (rng, compressed).
     */
    public static makeRandom(backend: CryptoBackend, network: Network, options?: RandomSignerOptions): ECPairSigner {
        let privateKeyBytes: Uint8Array;

        if (backend.generatePrivateKey && !options?.rng) {
            privateKeyBytes = backend.generatePrivateKey();
        } else {
            const rng =
                options?.rng ?? ((size: number) => crypto.getRandomValues(new Uint8Array(size)));
            do {
                privateKeyBytes = rng(32);
                if (privateKeyBytes.length !== 32) {
                    throw new TypeError(
                        `Expected 32 bytes from rng, got ${privateKeyBytes.length} bytes`,
                    );
                }
            } while (!backend.isPrivate(privateKeyBytes));
        }

        return ECPairSigner.fromPrivateKey(backend, createPrivateKey(privateKeyBytes), network, options);
    }

    /** Raw private key bytes, or `undefined` for public-key-only signers. */
    public get privateKey(): PrivateKey | undefined {
        return this.#privateKey;
    }

    /**
     * SEC1-encoded public key.  Lazily derived from the private key when
     * the signer was created via {@link fromPrivateKey} or {@link fromWIF}.
     *
     * @throws If neither a private nor public key is available (should never happen).
     */
    public get publicKey(): PublicKey {
        if (this.#publicKey === undefined) {
            const pk = this.#privateKey;
            if (pk === undefined) {
                throw new Error('Missing both private and public key');
            }
            const p = this.#backend.pointFromScalar(pk, this.#compressed);
            if (p === null) {
                throw new Error('Failed to derive public key from private key');
            }
            this.#publicKey = p;
        }
        return this.#publicKey;
    }

    /** 32-byte BIP-340 x-only public key (lazily derived and cached). */
    public get xOnlyPublicKey(): XOnlyPublicKey {
        if (this.#xOnlyPublicKey === undefined) {
            this.#xOnlyPublicKey = toXOnly(this.publicKey);
        }
        return this.#xOnlyPublicKey;
    }

    /** Network this signer is bound to. */
    public get network(): Network {
        return this.#network;
    }

    /** Whether the public key is in compressed SEC1 form. */
    public get compressed(): boolean {
        return this.#compressed;
    }

    /**
     * Bitmask of {@link SignerCapability} flags representing the operations
     * this signer can perform.  Lazily computed and cached.
     */
    public get capabilities(): number {
        if (this.#capabilities === undefined) {
            let caps = SignerCapability.EcdsaVerify | SignerCapability.PublicKeyTweak;
            if (this.#privateKey !== undefined) {
                caps |= SignerCapability.EcdsaSign | SignerCapability.PrivateKeyExport;
            }
            if (this.#backend.signSchnorr && this.#privateKey !== undefined) {
                caps |= SignerCapability.SchnorrSign;
            }
            if (this.#backend.verifySchnorr) {
                caps |= SignerCapability.SchnorrVerify;
            }
            this.#capabilities = caps;
        }
        return this.#capabilities;
    }

    /**
     * Tests whether this signer has a specific capability.
     * @param cap - {@link SignerCapability} flag to test.
     */
    public hasCapability(cap: SignerCapability): boolean {
        return (this.capabilities & cap) !== 0;
    }

    /**
     * Produces a compact ECDSA signature.
     *
     * When `lowR` is `true`, grinds the nonce until the R value's first
     * byte is `<= 0x7f`, producing a smaller DER encoding.
     *
     * @param hash - 32-byte message digest.
     * @param lowR - Enable low-R grinding.  Defaults to `false`.
     * @throws If this is a public-key-only signer.
     */
    public sign(hash: MessageHash, lowR?: boolean): Signature {
        if (this.#privateKey === undefined) throw new Error('Missing private key');
        if (!lowR) {
            return this.#backend.sign(hash, this.#privateKey);
        }
        let sig = this.#backend.sign(hash, this.#privateKey);
        const extraData = new Uint8Array(32);
        const view = new DataView(extraData.buffer, extraData.byteOffset, extraData.byteLength);
        let counter = 0;
        while (sig[0]! > 0x7f) {
            counter++;
            view.setUint32(0, counter, true);
            sig = this.#backend.sign(hash, this.#privateKey, extraData);
        }
        return sig;
    }

    /**
     * Produces a 64-byte BIP-340 Schnorr signature.
     *
     * @param hash - 32-byte message digest.
     * @throws If this is a public-key-only signer.
     * @throws If the backend does not support Schnorr signing.
     */
    public signSchnorr(hash: MessageHash): SchnorrSignature {
        if (this.#privateKey === undefined) throw new Error('Missing private key');
        if (!this.#backend.signSchnorr) {
            throw new Error('signSchnorr not supported by ecc library');
        }
        return this.#backend.signSchnorr(hash, this.#privateKey);
    }

    /**
     * Verifies a compact ECDSA signature against this signer's public key.
     *
     * @param hash - 32-byte message digest.
     * @param signature - Compact ECDSA signature.
     */
    public verify(hash: MessageHash, signature: Signature): boolean {
        return this.#backend.verify(hash, this.publicKey, signature);
    }

    /**
     * Verifies a BIP-340 Schnorr signature against this signer's x-only public key.
     *
     * @param hash - 32-byte message digest.
     * @param signature - 64-byte Schnorr signature.
     * @throws If the backend does not support Schnorr verification.
     */
    public verifySchnorr(hash: MessageHash, signature: SchnorrSignature): boolean {
        if (!this.#backend.verifySchnorr) {
            throw new Error('verifySchnorr not supported by ecc library');
        }
        return this.#backend.verifySchnorr(hash, this.xOnlyPublicKey, signature);
    }

    /**
     * Derives a new signer by applying a Taproot-style scalar tweak.
     *
     * When a private key is available the tweak is applied to the scalar
     * (negating first if the public key has odd Y).  Otherwise, only the
     * public key is tweaked via x-only point addition.
     *
     * @param t - 32-byte tweak scalar.
     * @throws If the tweaked key is invalid (e.g. lands on the point at infinity).
     */
    public tweak(t: Bytes32): ECPairSigner {
        assertBytes32(t);
        if (this.#privateKey !== undefined) {
            return this.#tweakFromPrivateKey(t);
        }
        return this.#tweakFromPublicKey(t);
    }

    /**
     * Exports the private key as a WIF string using this signer's network.
     *
     * @throws If this is a public-key-only signer.
     */
    public toWIF(): string {
        if (this.#privateKey === undefined) throw new Error('Missing private key');
        return encodeWIF(this.#privateKey, this.#compressed, this.#network);
    }

    #tweakFromPrivateKey(t: Bytes32): ECPairSigner {
        const pubKey = this.publicKey;
        const privateKey = this.#privateKey;
        if (privateKey === undefined) {
            throw new Error('Missing private key');
        }
        const effectiveKey = hasOddY(pubKey)
            ? this.#backend.privateNegate(privateKey)
            : privateKey;

        const tweakedPrivateKey = this.#backend.privateAdd(effectiveKey, t);
        if (tweakedPrivateKey === null) throw new Error('Invalid tweaked private key!');

        return ECPairSigner.fromPrivateKey(this.#backend, tweakedPrivateKey, this.#network, {
            compressed: this.#compressed,
        });
    }

    #tweakFromPublicKey(t: Bytes32): ECPairSigner {
        const xOnlyPubKey = this.xOnlyPublicKey;
        const tweakedPublicKey = this.#backend.xOnlyPointAddTweak(xOnlyPubKey, t);
        if (tweakedPublicKey === null || tweakedPublicKey.xOnlyPubkey === null) {
            throw new Error('Cannot tweak public key!');
        }
        const parityByte = new Uint8Array([tweakedPublicKey.parity === 0 ? 0x02 : 0x03]);
        const fullKey = concatBytes(parityByte, tweakedPublicKey.xOnlyPubkey);
        return ECPairSigner.fromPublicKey(this.#backend, createPublicKey(fullKey), this.#network, {
            compressed: this.#compressed,
        });
    }
}
