import type {
    Bytes20,
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    Satoshi,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';

/**
 * Decodes a hexadecimal string into a `Uint8Array`.
 *
 * @param hex - Even-length hex string (case-insensitive).
 * @returns Decoded bytes.
 * @throws {TypeError} On odd-length input or invalid hex characters.
 */
export function fromHexInternal(hex: string): Uint8Array {
    const len = hex.length;
    if (len % 2 !== 0) throw new TypeError('fromHexInternal: odd-length hex string');
    const out = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
        const hi = charToNibble(hex.charCodeAt(i));
        const lo = charToNibble(hex.charCodeAt(i + 1));
        if (hi === -1 || lo === -1) throw new TypeError('fromHexInternal: invalid hex character');
        out[i >> 1] = (hi << 4) | lo;
    }
    return out;
}

function charToNibble(c: number): number {
    if (c >= 48 && c <= 57) return c - 48;
    if (c >= 65 && c <= 70) return c - 55;
    if (c >= 97 && c <= 102) return c - 87;
    return -1;
}

/**
 * Returns `true` if every byte in `bytes` is zero.
 * @param bytes - Input to test.
 */
export function isZeroBytes(bytes: Uint8Array): boolean {
    for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] !== 0) return false;
    }
    return true;
}

/**
 * Lexicographic comparison of two byte arrays.
 *
 * @returns `-1` if `a < b`, `0` if equal, `1` if `a > b`.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const minLen = Math.min(a.length, b.length);
    for (let i = 0; i < minLen; i++) {
        const ai = a[i] as number;
        const bi = b[i] as number;
        if (ai < bi) return -1;
        if (ai > bi) return 1;
    }
    if (a.length < b.length) return -1;
    if (a.length > b.length) return 1;
    return 0;
}

/**
 * Returns `true` if `a` and `b` have identical length and contents.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Encodes `bytes` as a lowercase hexadecimal string.
 */
export function toHex(bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += (bytes[i] as number).toString(16).padStart(2, '0');
    }
    return hex;
}

/**
 * Concatenates one or more `Uint8Array` values into a single array.
 * @param arrays - Arrays to concatenate (in order).
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
        result.set(a, offset);
        offset += a.length;
    }
    return result;
}

/** secp256k1 curve order `n`. */
export const EC_N: bigint =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** secp256k1 field prime `p`. */
export const EC_P: bigint =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

/** Maximum satoshi value (`21_000_000 * 10^8`). */
export const SATOSHI_MAX: bigint = 21n * 10n ** 14n;

function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i] as number);
    }
    return result;
}

/**
 * Type guard for {@link Bytes32}.
 * @param value - Value to test.
 */
export function isBytes32(value: unknown): value is Bytes32 {
    return value instanceof Uint8Array && value.length === 32;
}

/**
 * Type guard for {@link Bytes20}.
 * @param value - Value to test.
 */
export function isBytes20(value: unknown): value is Bytes20 {
    return value instanceof Uint8Array && value.length === 20;
}

/**
 * Type guard for {@link PrivateKey}.
 *
 * Returns `true` when `value` is a 32-byte `Uint8Array` whose numeric
 * value falls in the range `[1, n)`.
 * @param value - Value to test.
 */
export function isPrivateKey(value: unknown): value is PrivateKey {
    if (!(value instanceof Uint8Array) || value.length !== 32) return false;
    if (isZeroBytes(value)) return false;
    const n = bytesToBigInt(value);
    return n < EC_N;
}

/**
 * Type guard for {@link PublicKey}.
 *
 * Accepts compressed (`02`/`03`, 33 bytes), uncompressed (`04`, 65 bytes),
 * and hybrid (`06`/`07`, 65 bytes) SEC1 encodings.
 * @param value - Value to test.
 */
export function isPublicKey(value: unknown): value is PublicKey {
    if (!(value instanceof Uint8Array)) return false;
    const prefix = value[0];
    if (value.length === 33 && (prefix === 0x02 || prefix === 0x03)) return true;
    if (
        value.length === 65 &&
        (prefix === 0x04 || prefix === 0x06 || prefix === 0x07)
    )
        return true;
    return false;
}

/**
 * Type guard for {@link XOnlyPublicKey}.
 *
 * Returns `true` when `value` is a non-zero 32-byte `Uint8Array`.
 * @param value - Value to test.
 */
export function isXOnlyPublicKey(value: unknown): value is XOnlyPublicKey {
    if (!(value instanceof Uint8Array) || value.length !== 32) return false;
    return !isZeroBytes(value);
}

/**
 * Type guard for {@link Signature}.
 *
 * Accepts compact ECDSA signatures (8 -- 73 bytes).
 * @param value - Value to test.
 */
export function isSignature(value: unknown): value is Signature {
    return value instanceof Uint8Array && value.length >= 8 && value.length <= 73;
}

/**
 * Type guard for {@link SchnorrSignature} (exactly 64 bytes).
 * @param value - Value to test.
 */
export function isSchnorrSignature(value: unknown): value is SchnorrSignature {
    return value instanceof Uint8Array && value.length === 64;
}

/**
 * Type guard for {@link MessageHash} (exactly 32 bytes).
 * @param value - Value to test.
 */
export function isMessageHash(value: unknown): value is MessageHash {
    return value instanceof Uint8Array && value.length === 32;
}

/**
 * Type guard for {@link Satoshi}.
 *
 * Returns `true` when `value` is a `bigint` in the range `[0, SATOSHI_MAX]`.
 * @param value - Value to test.
 */
export function isSatoshi(value: unknown): value is Satoshi {
    return typeof value === 'bigint' && value >= 0n && value <= SATOSHI_MAX;
}

/**
 * Asserts that `value` is a {@link Bytes32}.
 * @throws {TypeError} If the assertion fails.
 */
export function assertBytes32(value: unknown): asserts value is Bytes32 {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertBytes32: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(`assertBytes32: expected 32 bytes, got ${value.length} bytes`);
    }
}

/**
 * Asserts that `value` is a valid {@link PrivateKey} (32 bytes, in `[1, n)`).
 * @throws {TypeError} If the assertion fails.
 */
export function assertPrivateKey(value: unknown): asserts value is PrivateKey {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertPrivateKey: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(
            `assertPrivateKey: expected 32 bytes, got ${value.length} bytes`,
        );
    }
    if (isZeroBytes(value)) {
        throw new TypeError('assertPrivateKey: key is zero');
    }
    const n = bytesToBigInt(value);
    if (n >= EC_N) {
        throw new TypeError('assertPrivateKey: key not in range [1, n)');
    }
}

/**
 * Asserts that `value` is a valid SEC1-encoded {@link PublicKey}.
 * @throws {TypeError} If the assertion fails.
 */
export function assertPublicKey(value: unknown): asserts value is PublicKey {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertPublicKey: expected Uint8Array');
    }
    if (!isPublicKey(value)) {
        throw new TypeError(
            `assertPublicKey: invalid SEC1 public key (length=${value.length}, prefix=0x${(value[0] ?? 0).toString(16).padStart(2, '0')})`,
        );
    }
}

/**
 * Asserts that `value` is a valid {@link XOnlyPublicKey} (32 non-zero bytes).
 * @throws {TypeError} If the assertion fails.
 */
export function assertXOnlyPublicKey(value: unknown): asserts value is XOnlyPublicKey {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertXOnlyPublicKey: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(
            `assertXOnlyPublicKey: expected 32 bytes, got ${value.length} bytes`,
        );
    }
    if (isZeroBytes(value)) {
        throw new TypeError('assertXOnlyPublicKey: key is zero');
    }
}

/**
 * Asserts that `value` is a valid {@link MessageHash} (exactly 32 bytes).
 * @throws {TypeError} If the assertion fails.
 */
export function assertMessageHash(value: unknown): asserts value is MessageHash {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertMessageHash: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(
            `assertMessageHash: expected 32 bytes, got ${value.length} bytes`,
        );
    }
}

/**
 * Creates a branded {@link Bytes32} after validating length.
 * @param bytes - Raw bytes (must be exactly 32).
 * @throws {TypeError} If validation fails.
 */
export function createBytes32(bytes: Uint8Array): Bytes32 {
    assertBytes32(bytes);
    return bytes;
}

/**
 * Creates a branded {@link Bytes20} after validating length.
 * @param bytes - Raw bytes (must be exactly 20).
 * @throws {TypeError} If validation fails.
 */
export function createBytes20(bytes: Uint8Array): Bytes20 {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 20) {
        throw new TypeError(`createBytes20: expected 20 bytes Uint8Array`);
    }
    return bytes as Bytes20;
}

/**
 * Creates a branded {@link PrivateKey} after validating range `[1, n)`.
 * @param bytes - Raw bytes (must be 32 bytes, non-zero, `< n`).
 * @throws {TypeError} If validation fails.
 */
export function createPrivateKey(bytes: Uint8Array): PrivateKey {
    assertPrivateKey(bytes);
    return bytes;
}

/**
 * Creates a branded {@link PublicKey} after validating SEC1 encoding.
 * @param bytes - Compressed, uncompressed, or hybrid SEC1 public key.
 * @throws {TypeError} If validation fails.
 */
export function createPublicKey(bytes: Uint8Array): PublicKey {
    assertPublicKey(bytes);
    return bytes;
}

/**
 * Creates a branded {@link XOnlyPublicKey} after validating 32 non-zero bytes.
 * @param bytes - Raw 32-byte x-coordinate.
 * @throws {TypeError} If validation fails.
 */
export function createXOnlyPublicKey(bytes: Uint8Array): XOnlyPublicKey {
    assertXOnlyPublicKey(bytes);
    return bytes;
}

/**
 * Creates a branded {@link Signature} after validating length (8 -- 73 bytes).
 * @param bytes - Compact ECDSA signature bytes.
 * @throws {TypeError} If validation fails.
 */
export function createSignature(bytes: Uint8Array): Signature {
    if (!isSignature(bytes)) {
        throw new TypeError(
            `createSignature: expected 8-73 bytes, got ${bytes.length} bytes`,
        );
    }
    return bytes;
}

/**
 * Creates a branded {@link SchnorrSignature} after validating 64-byte length.
 * @param bytes - BIP-340 Schnorr signature bytes.
 * @throws {TypeError} If validation fails.
 */
export function createSchnorrSignature(bytes: Uint8Array): SchnorrSignature {
    if (!isSchnorrSignature(bytes)) {
        throw new TypeError(
            `createSchnorrSignature: expected 64 bytes, got ${bytes.length} bytes`,
        );
    }
    return bytes;
}

/**
 * Creates a branded {@link MessageHash} after validating 32-byte length.
 * @param bytes - Hash digest bytes.
 * @throws {TypeError} If validation fails.
 */
export function createMessageHash(bytes: Uint8Array): MessageHash {
    assertMessageHash(bytes);
    return bytes;
}

/**
 * Creates a branded {@link Satoshi} after validating `[0, SATOSHI_MAX]`.
 * @param value - Amount in satoshis.
 * @throws {TypeError} If `value` is out of range.
 */
export function createSatoshi(value: bigint): Satoshi {
    if (!isSatoshi(value)) {
        throw new TypeError(`createSatoshi: value out of range [0, ${SATOSHI_MAX}]`);
    }
    return value;
}
