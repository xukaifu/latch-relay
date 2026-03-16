import { describe, it, expect } from 'vitest';
import {
    derivePairingParams,
    spake2Start,
    spake2Finish,
    computeChallengeMac,
    encrypt,
    decrypt,
    hkdfExtract,
    hkdfExpand,
} from '../src/crypto.js';

function randomBytes(n: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(n));
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

describe('PBKDF2 derivation', () => {
    it('produces deterministic pairingId and w from a code', async () => {
        const a = await derivePairingParams('TESTCODE');
        const b = await derivePairingParams('TESTCODE');
        expect(a.pairingId).toBe(b.pairingId);
        expect(a.w).toBe(b.w);
        expect(a.pairingId.length).toBe(64); // 32 bytes hex
        expect(a.w).toBeGreaterThan(0n);
    });

    it('is case-insensitive', async () => {
        const a = await derivePairingParams('testcode');
        const b = await derivePairingParams('TESTCODE');
        expect(a.pairingId).toBe(b.pairingId);
        expect(a.w).toBe(b.w);
    });
});

describe('HKDF', () => {
    it('extract + expand produce deterministic output', async () => {
        const salt = new TextEncoder().encode('salt');
        const ikm = new TextEncoder().encode('ikm');
        const prk = await hkdfExtract(salt, ikm);
        expect(prk.length).toBe(32);
        const okm = await hkdfExpand(prk, 'info', 64);
        expect(okm.length).toBe(64);
        // Deterministic
        const okm2 = await hkdfExpand(prk, 'info', 64);
        expect(arraysEqual(okm, okm2)).toBe(true);
    });

    it('different info produces different output', async () => {
        const salt = new TextEncoder().encode('salt');
        const ikm = new TextEncoder().encode('ikm');
        const prk = await hkdfExtract(salt, ikm);
        const a = await hkdfExpand(prk, 'a', 32);
        const b = await hkdfExpand(prk, 'b', 32);
        expect(arraysEqual(a, b)).toBe(false);
    });
});

describe('SPAKE2 key agreement', () => {
    it('initiator and responder derive same channelId and encKey', async () => {
        const { pairingId, w } = await derivePairingParams('AGREEMENT');

        const initiator = spake2Start(w, 'initiator');
        const responder = spake2Start(w, 'responder');

        expect(initiator.pubShare.length).toBe(65);
        expect(responder.pubShare.length).toBe(65);
        expect(initiator.pubShare[0]).toBe(0x04);
        expect(responder.pubShare[0]).toBe(0x04);

        const iKeys = await spake2Finish(initiator, responder.pubShare, w, pairingId, '', '');
        const rKeys = await spake2Finish(responder, initiator.pubShare, w, pairingId, '', '');

        expect(iKeys.channelId).toBe(rKeys.channelId);
        expect(arraysEqual(iKeys.encKey, rKeys.encKey)).toBe(true);
        expect(iKeys.channelId.length).toBe(64);
        expect(iKeys.encKey.length).toBe(32);
    });

    it('different codes produce different keys', async () => {
        const p1 = await derivePairingParams('CODE1');
        const p2 = await derivePairingParams('CODE2');

        const i1 = spake2Start(p1.w, 'initiator');
        const r1 = spake2Start(p1.w, 'responder');
        const keys1 = await spake2Finish(i1, r1.pubShare, p1.w, p1.pairingId, '', '');

        const i2 = spake2Start(p2.w, 'initiator');
        const r2 = spake2Start(p2.w, 'responder');
        const keys2 = await spake2Finish(i2, r2.pubShare, p2.w, p2.pairingId, '', '');

        expect(keys1.channelId).not.toBe(keys2.channelId);
    });
});

describe('HMAC challenge MAC', () => {
    it('produces deterministic 32-byte MAC', async () => {
        const key = randomBytes(32);
        const nonce = randomBytes(32);
        const mac1 = await computeChallengeMac(key, 'channel1', nonce, 'peer1', 'initiator');
        const mac2 = await computeChallengeMac(key, 'channel1', nonce, 'peer1', 'initiator');
        expect(mac1.length).toBe(32);
        expect(arraysEqual(mac1, mac2)).toBe(true);
    });

    it('different inputs produce different MACs', async () => {
        const key = randomBytes(32);
        const nonce = randomBytes(32);
        const mac1 = await computeChallengeMac(key, 'ch1', nonce, 'peer1', 'initiator');
        const mac2 = await computeChallengeMac(key, 'ch2', nonce, 'peer1', 'initiator');
        expect(arraysEqual(mac1, mac2)).toBe(false);
    });
});

describe('AES-256-GCM', () => {
    it('round-trip encrypt/decrypt', async () => {
        const key = randomBytes(32);
        const channelId = 'test-channel';
        const plaintext = new TextEncoder().encode('Hello, encrypted world!');
        const ciphertext = await encrypt(key, channelId, plaintext);
        expect(ciphertext.length).toBeGreaterThan(plaintext.length);
        const decrypted = await decrypt(key, channelId, ciphertext);
        expect(arraysEqual(decrypted, plaintext)).toBe(true);
    });

    it('wrong key fails decryption', async () => {
        const key1 = randomBytes(32);
        const key2 = randomBytes(32);
        const ciphertext = await encrypt(key1, 'ch', new TextEncoder().encode('secret'));
        await expect(decrypt(key2, 'ch', ciphertext)).rejects.toThrow();
    });

    it('wrong channelId (AAD) fails decryption', async () => {
        const key = randomBytes(32);
        const ciphertext = await encrypt(key, 'ch1', new TextEncoder().encode('secret'));
        await expect(decrypt(key, 'ch2', ciphertext)).rejects.toThrow();
    });

    it('empty plaintext round-trips', async () => {
        const key = randomBytes(32);
        const ciphertext = await encrypt(key, 'ch', new Uint8Array(0));
        const decrypted = await decrypt(key, 'ch', ciphertext);
        expect(decrypted.length).toBe(0);
    });
});
