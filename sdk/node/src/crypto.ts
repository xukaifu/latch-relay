import crypto from 'node:crypto';
import { p256 } from '@noble/curves/p256';

const P256_ORDER = p256.CURVE.n;
const Point = p256.ProjectivePoint;
type ProjectivePoint = typeof Point.BASE;

// RFC 9382 Section 4: M and N for P-256
const M = Point.fromHex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
const N = Point.fromHex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');

function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    for (const b of bytes) {
        result = (result << 8n) | BigInt(b);
    }
    return result;
}

function hkdfExtract(hash: string, salt: Buffer, ikm: Buffer): Buffer {
    return Buffer.from(crypto.createHmac(hash.replace('-', ''), salt).update(ikm).digest());
}

function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
    const hashLen = 32; // SHA-256
    const n = Math.ceil(length / hashLen);
    const infoBuffer = Buffer.from(info);
    const okm = Buffer.alloc(n * hashLen);
    let prev = Buffer.alloc(0);

    for (let i = 1; i <= n; i++) {
        prev = Buffer.from(
            crypto.createHmac('sha256', prk)
                .update(prev)
                .update(infoBuffer)
                .update(Buffer.from([i]))
                .digest()
        );
        prev.copy(okm, (i - 1) * hashLen);
    }

    return okm.subarray(0, length);
}

function writeLE64(value: number): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeUInt32LE(value, 0);
    buf.writeUInt32LE(0, 4);
    return buf;
}

function ttConcat(parts: Buffer[]): Buffer {
    const segments: Buffer[] = [];
    for (const part of parts) {
        segments.push(writeLE64(part.length));
        segments.push(part);
    }
    return Buffer.concat(segments);
}

export interface PairingParams {
    pairingId: string;
    w: bigint;
}

function derivePairingParamsForWindow(code: string, window: number): PairingParams {
    const seed = crypto.pbkdf2Sync(
        code.toUpperCase(),
        `latch-relay-room-v1${window}`,
        100000,
        32,
        'sha256'
    );
    const seedBuf = Buffer.from(seed);
    const pairingId = hkdfExpand(seedBuf, 'roomId', 32).toString('hex');
    const wBytes = hkdfExpand(seedBuf, 'spake2-w', 48);
    const w = bytesToBigInt(wBytes) % P256_ORDER;
    if (w === 0n) {
        throw new Error('derived w is zero');
    }
    return { pairingId, w };
}

export function derivePairingParams(code: string): PairingParams {
    const window = Math.floor(Date.now() / 1000 / 600);
    return derivePairingParamsForWindow(code, window);
}

export function derivePairingParamsBothWindows(code: string): { current: PairingParams; previous: PairingParams } {
    const window = Math.floor(Date.now() / 1000 / 600);
    return {
        current: derivePairingParamsForWindow(code, window),
        previous: derivePairingParamsForWindow(code, window - 1),
    };
}

export interface Spake2State {
    scalar: bigint;
    pubShare: Buffer; // uncompressed SEC1 (65 bytes)
    role: 'initiator' | 'responder';
}

export function spake2Start(w: bigint, role: 'initiator' | 'responder'): Spake2State {
    const scalarBytes = p256.utils.randomPrivateKey();
    const scalar = bytesToBigInt(scalarBytes);
    const xG = Point.BASE.multiply(scalar);
    // Both peers blind with M (pubShare is sent before role assignment)
    const blind = M.multiply(w);
    const pubPoint = xG.add(blind);
    const pubShare = Buffer.from(pubPoint.toRawBytes(false)); // uncompressed
    return { scalar, pubShare, role };
}

export interface Spake2Keys {
    channelId: string;
    encKey: Buffer;
}

export function spake2Finish(
    state: Spake2State,
    peerPubShareBytes: Buffer,
    w: bigint,
    pairingId: string,
    myId: string,
    peerId: string,
): Spake2Keys {
    const peerPub = Point.fromHex(peerPubShareBytes);
    // Both peers blinded with M, so always remove w*M
    const unblind = M.multiply(w);
    const K = peerPub.subtract(unblind).multiply(state.scalar);

    // Build transcript TT
    const context = Buffer.from('latch-relay-v1' + pairingId);

    // Determine prover/verifier IDs based on role
    let idProver: Buffer, idVerifier: Buffer;
    if (state.role === 'initiator') {
        idProver = Buffer.from(myId);
        idVerifier = Buffer.from(peerId);
    } else {
        idProver = Buffer.from(peerId);
        idVerifier = Buffer.from(myId);
    }

    const mBytes = Buffer.from(M.toRawBytes(false));
    const nBytes = Buffer.from(N.toRawBytes(false));

    let pA: Buffer, pB: Buffer;
    if (state.role === 'initiator') {
        pA = state.pubShare;
        pB = peerPubShareBytes;
    } else {
        pA = peerPubShareBytes;
        pB = state.pubShare;
    }
    const kBytes = Buffer.from(K.toRawBytes(false));

    const tt = ttConcat([context, idProver, idVerifier, mBytes, nBytes, pA, pB, kBytes]);
    const Ke = crypto.createHash('sha256').update(tt).digest();

    const ISK = hkdfExtract('sha256', Buffer.from('latch-relay-isk' + pairingId), Buffer.from(Ke));
    const channelId = hkdfExpand(ISK, 'channel', 32).toString('hex');
    const encKey = hkdfExpand(ISK, 'encrypt', 32);

    return { channelId, encKey };
}

export function computeChallengeMac(
    encKey: Buffer,
    channelId: string,
    nonce: Buffer,
    id: string,
    role: string
): Buffer {
    const payload = Buffer.concat([
        Buffer.from('challenge\0'),
        Buffer.from(channelId + '\0'),
        nonce,
        Buffer.from('\0' + id + '\0' + role),
    ]);
    return Buffer.from(crypto.createHmac('sha256', encKey).update(payload).digest());
}

export function encrypt(encKey: Buffer, channelId: string, plaintext: Buffer): Buffer {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, nonce);
    cipher.setAAD(Buffer.from(channelId));
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, encrypted, tag]);
}

export function decrypt(encKey: Buffer, channelId: string, ciphertext: Buffer): Buffer {
    if (ciphertext.length < 28) {
        throw new Error('ciphertext too short: must be at least 28 bytes (12 nonce + 16 tag)');
    }
    const nonce = ciphertext.subarray(0, 12);
    const tag = ciphertext.subarray(ciphertext.length - 16);
    const data = ciphertext.subarray(12, ciphertext.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, nonce);
    decipher.setAAD(Buffer.from(channelId));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}

// Exported for testing
export { hkdfExtract, hkdfExpand };
