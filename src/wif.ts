import type { PrivateKey } from './branded.js';
import type { Network } from './networks.js';
import { createPrivateKey } from './types.js';
import { decode, encode } from '@btc-vision/wif';

/**
 * Result of decoding a WIF-encoded private key via {@link decodeWIF}.
 */
export interface WifDecodeResult {
    /** The decoded 32-byte private key. */
    readonly privateKey: PrivateKey;
    /** Whether the key was encoded as compressed. */
    readonly compressed: boolean;
    /** The network whose WIF version byte matched. */
    readonly network: Network;
}

/**
 * Encodes a private key into Wallet Import Format (WIF / Base58Check).
 *
 * @param privateKey - 32-byte private key to encode.
 * @param compressed - `true` to flag the key as compressed.
 * @param network - Network whose {@link Network.wif | wif} version byte to use.
 * @returns The WIF-encoded string.
 */
export function encodeWIF(privateKey: PrivateKey, compressed: boolean, network: Network): string {
    return encode({
        version: network.wif,
        privateKey,
        compressed,
    });
}

/**
 * Decodes a WIF-encoded private key string.
 *
 * When `network` is a single {@link Network}, the decoded version byte must
 * match exactly or an error is thrown.  When `network` is an array, the first
 * network whose {@link Network.wif | wif} byte matches is used.
 *
 * @param wifString - The WIF string to decode.
 * @param network - One or more candidate networks.
 * @returns The decoded private key, compression flag, and matched network.
 * @throws If no network matches the decoded version byte.
 */
export function decodeWIF(
    wifString: string,
    network: Network | readonly Network[],
): WifDecodeResult {
    const decoded = decode(wifString);
    const version = decoded.version;

    if (Array.isArray(network)) {
        const nets = network as readonly Network[];
        const matched = nets.find((n) => n.wif === version);
        if (!matched) throw new Error('Unknown network version');
        return {
            privateKey: createPrivateKey(decoded.privateKey),
            compressed: decoded.compressed,
            network: matched,
        };
    }

    const net = network as Network;
    if (version !== net.wif) {
        throw new Error('Invalid network version');
    }
    return {
        privateKey: createPrivateKey(decoded.privateKey),
        compressed: decoded.compressed,
        network: net,
    };
}
