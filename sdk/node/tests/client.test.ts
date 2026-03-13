import { describe, it, expect } from 'vitest';
import {
    derivePairingParams,
    spake2Start,
    spake2Finish,
    computeChallengeMac,
    encrypt,
    decrypt,
} from '../src/crypto.js';

describe('full pairing simulation (no server)', () => {
    it('two peers can derive shared keys and verify each other', () => {
        const code = 'SIMTEST';
        const paramsA = derivePairingParams(code);
        const paramsB = derivePairingParams(code);
        expect(paramsA.pairingId).toBe(paramsB.pairingId);

        // SPAKE2 exchange
        const stateA = spake2Start(paramsA.w, 'initiator');
        const stateB = spake2Start(paramsB.w, 'responder');

        const keysA = spake2Finish(stateA, stateB.pubShare, paramsA.w, paramsA.pairingId, '', '');
        const keysB = spake2Finish(stateB, stateA.pubShare, paramsB.w, paramsB.pairingId, '', '');

        expect(keysA.channelId).toBe(keysB.channelId);
        expect(keysA.encKey.equals(keysB.encKey)).toBe(true);

        // Challenge-response
        const nonceA = Buffer.from('a'.repeat(32));
        const nonceB = Buffer.from('b'.repeat(32));

        const macA = computeChallengeMac(keysA.encKey, keysA.channelId, nonceA, 'peerA', 'initiator');
        const macB = computeChallengeMac(keysB.encKey, keysB.channelId, nonceB, 'peerB', 'responder');

        // Each side verifies the other's MAC
        const expectedMacA = computeChallengeMac(keysB.encKey, keysB.channelId, nonceA, 'peerA', 'initiator');
        const expectedMacB = computeChallengeMac(keysA.encKey, keysA.channelId, nonceB, 'peerB', 'responder');

        expect(macA.equals(expectedMacA)).toBe(true);
        expect(macB.equals(expectedMacB)).toBe(true);

        // Encrypted message exchange
        const msg = Buffer.from('Hello from A to B');
        const ciphertext = encrypt(keysA.encKey, keysA.channelId, msg);
        const decrypted = decrypt(keysB.encKey, keysB.channelId, ciphertext);
        expect(decrypted.equals(msg)).toBe(true);
    });
});
