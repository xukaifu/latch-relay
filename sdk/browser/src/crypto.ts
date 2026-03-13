import { p256 } from '@noble/curves/p256';

const P256_ORDER = p256.CURVE.n;
const Point = p256.ProjectivePoint;
type ProjectivePoint = typeof Point.BASE;

// RFC 9382 Section 4: M and N for P-256
const M = Point.fromHex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
const N = Point.fromHex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');

// --- Uint8Array helpers ---

function concat(...arrays: Uint8Array[]): Uint8Array {
    const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
        result.set(a, offset);
        offset += a.length;
    }
    return result;
}

function toBase64url(bytes: Uint8Array): string {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(s: string): Uint8Array {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function toHex(bytes: Uint8Array): string {
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    return hex;
}

function textEncode(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    for (const b of bytes) {
        result = (result << 8n) | BigInt(b);
    }
    return result;
}

// Best-effort constant-time comparison. JS JIT may optimize this;
// no true constant-time guarantee exists in pure JS (unlike Node's C binding).
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// --- HMAC / Hash via Web Crypto ---

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, data as BufferSource);
    return new Uint8Array(sig);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

// --- HKDF ---

async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
    return hmacSha256(salt, ikm);
}

async function hkdfExpand(prk: Uint8Array, info: string, length: number): Promise<Uint8Array> {
    const hashLen = 32;
    const n = Math.ceil(length / hashLen);
    const infoBytes = textEncode(info);
    const okm = new Uint8Array(n * hashLen);
    let prev: Uint8Array = new Uint8Array(0);

    for (let i = 1; i <= n; i++) {
        prev = new Uint8Array(await hmacSha256(prk, concat(prev, infoBytes, new Uint8Array([i]))));
        okm.set(prev, (i - 1) * hashLen);
    }

    return okm.subarray(0, length);
}

// --- Transcript helpers ---

function writeLE64(value: number): Uint8Array {
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    view.setUint32(0, value, true);
    view.setUint32(4, 0, true);
    return buf;
}

function ttConcat(parts: Uint8Array[]): Uint8Array {
    const segments: Uint8Array[] = [];
    for (const part of parts) {
        segments.push(writeLE64(part.length));
        segments.push(part);
    }
    return concat(...segments);
}

// --- PBKDF2 via Web Crypto ---

async function pbkdf2(password: string, salt: string, iterations: number, keyLen: number): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey('raw', textEncode(password) as BufferSource, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: textEncode(salt) as BufferSource, iterations, hash: 'SHA-256' },
        key,
        keyLen * 8,
    );
    return new Uint8Array(bits);
}

// --- Pairing params ---

export interface PairingParams {
    pairingId: string;
    w: bigint;
}

async function derivePairingParamsForWindow(code: string, window: number): Promise<PairingParams> {
    const seed = await pbkdf2(code.toUpperCase(), `latch-relay-room-v1${window}`, 100000, 32);
    const pairingId = toHex(await hkdfExpand(seed, 'roomId', 32));
    const wBytes = await hkdfExpand(seed, 'spake2-w', 48);
    const w = bytesToBigInt(wBytes) % P256_ORDER;
    if (w === 0n) {
        throw new Error('derived w is zero');
    }
    return { pairingId, w };
}

export async function derivePairingParams(code: string): Promise<PairingParams> {
    const window = Math.floor(Date.now() / 1000 / 600);
    return derivePairingParamsForWindow(code, window);
}

export async function derivePairingParamsBothWindows(code: string): Promise<{ current: PairingParams; previous: PairingParams }> {
    const window = Math.floor(Date.now() / 1000 / 600);
    const [current, previous] = await Promise.all([
        derivePairingParamsForWindow(code, window),
        derivePairingParamsForWindow(code, window - 1),
    ]);
    return { current, previous };
}

// --- SPAKE2 ---

export interface Spake2State {
    scalar: bigint;
    pubShare: Uint8Array; // uncompressed SEC1 (65 bytes)
    role: 'initiator' | 'responder';
}

export function spake2Start(w: bigint, role: 'initiator' | 'responder'): Spake2State {
    const scalarBytes = p256.utils.randomPrivateKey();
    const scalar = bytesToBigInt(scalarBytes);
    const xG = Point.BASE.multiply(scalar);
    const blind = M.multiply(w);
    const pubPoint = xG.add(blind);
    const pubShare = pubPoint.toRawBytes(false); // uncompressed
    return { scalar, pubShare, role };
}

export interface Spake2Keys {
    channelId: string;
    encKey: Uint8Array;
}

export async function spake2Finish(
    state: Spake2State,
    peerPubShareBytes: Uint8Array,
    w: bigint,
    pairingId: string,
    myId: string,
    peerId: string,
): Promise<Spake2Keys> {
    const peerPub = Point.fromHex(peerPubShareBytes);
    const unblind = M.multiply(w);
    const K = peerPub.subtract(unblind).multiply(state.scalar);

    const context = textEncode('latch-relay-v1' + pairingId);

    let idProver: Uint8Array, idVerifier: Uint8Array;
    if (state.role === 'initiator') {
        idProver = textEncode(myId);
        idVerifier = textEncode(peerId);
    } else {
        idProver = textEncode(peerId);
        idVerifier = textEncode(myId);
    }

    const mBytes = M.toRawBytes(false);
    const nBytes = N.toRawBytes(false);

    let pA: Uint8Array, pB: Uint8Array;
    if (state.role === 'initiator') {
        pA = state.pubShare;
        pB = peerPubShareBytes;
    } else {
        pA = peerPubShareBytes;
        pB = state.pubShare;
    }
    const kBytes = K.toRawBytes(false);

    const tt = ttConcat([context, idProver, idVerifier, mBytes, nBytes, pA, pB, kBytes]);
    const Ke = await sha256(tt);

    const ISK = await hkdfExtract(textEncode('latch-relay-isk' + pairingId), Ke);
    const channelId = toHex(await hkdfExpand(ISK, 'channel', 32));
    const encKey = await hkdfExpand(ISK, 'encrypt', 32);

    return { channelId, encKey };
}

export async function computeChallengeMac(
    encKey: Uint8Array,
    channelId: string,
    nonce: Uint8Array,
    id: string,
    role: string
): Promise<Uint8Array> {
    const payload = concat(
        textEncode('challenge\0'),
        textEncode(channelId + '\0'),
        nonce,
        textEncode('\0' + id + '\0' + role),
    );
    return hmacSha256(encKey, payload);
}

export async function encrypt(encKey: Uint8Array, channelId: string, plaintext: Uint8Array): Promise<Uint8Array> {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', encKey as BufferSource, 'AES-GCM', false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: textEncode(channelId) as BufferSource },
        key,
        plaintext as BufferSource,
    );
    // AES-GCM output includes the tag appended
    return concat(nonce, new Uint8Array(ciphertext));
}

export async function decrypt(encKey: Uint8Array, channelId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
    if (ciphertext.length < 28) {
        throw new Error('ciphertext too short: must be at least 28 bytes (12 nonce + 16 tag)');
    }
    const nonce = ciphertext.subarray(0, 12);
    const data = ciphertext.subarray(12); // Web Crypto expects tag appended to ciphertext
    const key = await crypto.subtle.importKey('raw', encKey as BufferSource, 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: textEncode(channelId) as BufferSource },
        key,
        data as BufferSource,
    );
    return new Uint8Array(plaintext);
}

// Exported for external use
export { toBase64url, fromBase64url, toHex, timingSafeEqual, hkdfExtract, hkdfExpand };
