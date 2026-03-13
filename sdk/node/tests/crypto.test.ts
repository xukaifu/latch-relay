import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
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

describe('PBKDF2 derivation', () => {
    it('produces deterministic pairingId and w from a code', () => {
        const a = derivePairingParams('TESTCODE');
        const b = derivePairingParams('TESTCODE');
        expect(a.pairingId).toBe(b.pairingId);
        expect(a.w).toBe(b.w);
        expect(a.pairingId.length).toBe(64); // 32 bytes hex
        expect(a.w).toBeGreaterThan(0n);
    });

    it('is case-insensitive', () => {
        const a = derivePairingParams('testcode');
        const b = derivePairingParams('TESTCODE');
        expect(a.pairingId).toBe(b.pairingId);
        expect(a.w).toBe(b.w);
    });
});

describe('HKDF', () => {
    it('extract + expand produce deterministic output', () => {
        const prk = hkdfExtract('sha256', Buffer.from('salt'), Buffer.from('ikm'));
        expect(prk.length).toBe(32);
        const okm = hkdfExpand(prk, 'info', 64);
        expect(okm.length).toBe(64);
        // Deterministic
        const okm2 = hkdfExpand(prk, 'info', 64);
        expect(okm.equals(okm2)).toBe(true);
    });

    it('different info produces different output', () => {
        const prk = hkdfExtract('sha256', Buffer.from('salt'), Buffer.from('ikm'));
        const a = hkdfExpand(prk, 'a', 32);
        const b = hkdfExpand(prk, 'b', 32);
        expect(a.equals(b)).toBe(false);
    });
});

describe('SPAKE2 key agreement', () => {
    it('initiator and responder derive same channelId and encKey', () => {
        const { pairingId, w } = derivePairingParams('AGREEMENT');

        const initiator = spake2Start(w, 'initiator');
        const responder = spake2Start(w, 'responder');

        expect(initiator.pubShare.length).toBe(65);
        expect(responder.pubShare.length).toBe(65);
        expect(initiator.pubShare[0]).toBe(0x04);
        expect(responder.pubShare[0]).toBe(0x04);

        const iKeys = spake2Finish(initiator, responder.pubShare, w, pairingId, '', '');
        const rKeys = spake2Finish(responder, initiator.pubShare, w, pairingId, '', '');

        expect(iKeys.channelId).toBe(rKeys.channelId);
        expect(iKeys.encKey.equals(rKeys.encKey)).toBe(true);
        expect(iKeys.channelId.length).toBe(64);
        expect(iKeys.encKey.length).toBe(32);
    });

    it('different codes produce different keys', () => {
        const p1 = derivePairingParams('CODE1');
        const p2 = derivePairingParams('CODE2');

        const i1 = spake2Start(p1.w, 'initiator');
        const r1 = spake2Start(p1.w, 'responder');
        const keys1 = spake2Finish(i1, r1.pubShare, p1.w, p1.pairingId, '', '');

        const i2 = spake2Start(p2.w, 'initiator');
        const r2 = spake2Start(p2.w, 'responder');
        const keys2 = spake2Finish(i2, r2.pubShare, p2.w, p2.pairingId, '', '');

        expect(keys1.channelId).not.toBe(keys2.channelId);
    });
});

describe('HMAC challenge MAC', () => {
    it('produces deterministic 32-byte MAC', () => {
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(32);
        const mac1 = computeChallengeMac(key, 'channel1', nonce, 'peer1', 'initiator');
        const mac2 = computeChallengeMac(key, 'channel1', nonce, 'peer1', 'initiator');
        expect(mac1.length).toBe(32);
        expect(mac1.equals(mac2)).toBe(true);
    });

    it('different inputs produce different MACs', () => {
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(32);
        const mac1 = computeChallengeMac(key, 'ch1', nonce, 'peer1', 'initiator');
        const mac2 = computeChallengeMac(key, 'ch2', nonce, 'peer1', 'initiator');
        expect(mac1.equals(mac2)).toBe(false);
    });
});

describe('AES-256-GCM', () => {
    it('round-trip encrypt/decrypt', () => {
        const key = crypto.randomBytes(32);
        const channelId = 'test-channel';
        const plaintext = Buffer.from('Hello, encrypted world!');
        const ciphertext = encrypt(key, channelId, plaintext);
        expect(ciphertext.length).toBeGreaterThan(plaintext.length);
        const decrypted = decrypt(key, channelId, ciphertext);
        expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('wrong key fails decryption', () => {
        const key1 = crypto.randomBytes(32);
        const key2 = crypto.randomBytes(32);
        const ciphertext = encrypt(key1, 'ch', Buffer.from('secret'));
        expect(() => decrypt(key2, 'ch', ciphertext)).toThrow();
    });

    it('wrong channelId (AAD) fails decryption', () => {
        const key = crypto.randomBytes(32);
        const ciphertext = encrypt(key, 'ch1', Buffer.from('secret'));
        expect(() => decrypt(key, 'ch2', ciphertext)).toThrow();
    });

    it('empty plaintext round-trips', () => {
        const key = crypto.randomBytes(32);
        const ciphertext = encrypt(key, 'ch', Buffer.alloc(0));
        const decrypted = decrypt(key, 'ch', ciphertext);
        expect(decrypted.length).toBe(0);
    });
});
