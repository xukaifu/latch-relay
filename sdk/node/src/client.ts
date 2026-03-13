import crypto from 'node:crypto';
import WebSocket from 'ws';
import {
    derivePairingParams,
    derivePairingParamsBothWindows,
    spake2Start,
    spake2Finish,
    computeChallengeMac,
    encrypt,
    decrypt,
} from './crypto.js';

export interface ChannelState {
    channelId: string;
    encKey: Buffer;
    role: 'initiator' | 'responder';
    peerId: string;
    active: boolean;
}

interface InMsg {
    type: string;
    ch?: string;
    pubShare?: string;
    id?: string;
    role?: string;
    nonce?: string;
    peerNonce?: string;
    peerMac?: string;
    peerId?: string;
    peerRole?: string;
    data?: string;
    code?: string;
    message?: string;
}

type Resolver = (msg: InMsg) => void;

export class LatchClient {
    private ws: WebSocket | null = null;
    private serverUrl: string;
    private id: string;
    private channels = new Map<string, ChannelState>();
    private waiters = new Map<string, Resolver[]>();
    private globalWaiters: Resolver[] = [];

    onMessage?: (channelId: string, peerId: string, data: Buffer) => void;

    constructor(serverUrl: string, id: string) {
        this.serverUrl = serverUrl;
        this.id = id;
    }

    async connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.serverUrl);
            this.ws.on('open', () => resolve());
            this.ws.on('error', (err) => reject(err));
            this.ws.on('message', (raw) => {
                const msg: InMsg = JSON.parse(raw.toString());
                this.dispatch(msg);
            });
        });
    }

    private dispatch(msg: InMsg): void {
        // Handle relayed messages
        if (msg.type === 'message' && msg.ch && msg.data) {
            const ch = this.channels.get(msg.ch);
            if (ch && this.onMessage) {
                const ciphertext = Buffer.from(msg.data, 'base64url');
                try {
                    const plaintext = decrypt(ch.encKey, ch.channelId, ciphertext);
                    this.onMessage(ch.channelId, msg.peerId ?? '', plaintext);
                } catch {
                    // Ignore decryption failures
                }
            }
            return;
        }

        // Dispatch to waiters by type, then by ch
        const key = msg.ch ? `${msg.type}:${msg.ch}` : msg.type;
        const typeWaiters = this.waiters.get(key);
        if (typeWaiters && typeWaiters.length > 0) {
            const resolver = typeWaiters.shift()!;
            resolver(msg);
            return;
        }

        // Global waiters
        if (this.globalWaiters.length > 0) {
            const resolver = this.globalWaiters.shift()!;
            resolver(msg);
            return;
        }
    }

    private waitFor(key: string, timeoutMs = 30000): Promise<InMsg> {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`timeout waiting for ${key}`)), timeoutMs);
            const resolver: Resolver = (msg) => {
                clearTimeout(timer);
                resolve(msg);
            };
            if (!this.waiters.has(key)) {
                this.waiters.set(key, []);
            }
            this.waiters.get(key)!.push(resolver);
        });
    }

    private waitForAny(keys: string[], timeoutMs = 30000): Promise<InMsg> {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`timeout waiting for ${keys.join('|')}`)), timeoutMs);
            let resolved = false;

            const resolver: Resolver = (msg) => {
                if (resolved) return;
                resolved = true;
                clearTimeout(timer);
                // Remove this resolver from all keys
                for (const k of keys) {
                    const list = this.waiters.get(k);
                    if (list) {
                        const idx = list.indexOf(resolver);
                        if (idx >= 0) list.splice(idx, 1);
                    }
                }
                resolve(msg);
            };

            for (const key of keys) {
                if (!this.waiters.has(key)) {
                    this.waiters.set(key, []);
                }
                this.waiters.get(key)!.push(resolver);
            }
        });
    }

    private sendRaw(msg: Record<string, unknown>): void {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error('WebSocket not connected');
        }
        this.ws.send(JSON.stringify(msg));
    }

    async pair(code: string): Promise<ChannelState> {
        const { current, previous } = derivePairingParamsBothWindows(code);
        try {
            return await this.pairWithParams(current.pairingId, current.w);
        } catch {
            return await this.pairWithParams(previous.pairingId, previous.w);
        }
    }

    private async pairWithParams(pairingId: string, w: bigint): Promise<ChannelState> {
        const state = spake2Start(w, 'initiator');

        // Send pair message
        this.sendRaw({
            type: 'pair',
            ch: pairingId,
            id: this.id,
            pubShare: Buffer.from(state.pubShare).toString('base64url'),
        });

        // Wait for pair_matched
        const matched = await this.waitFor(`pair_matched:${pairingId}`);
        const myRole = (matched.role as 'initiator' | 'responder') ?? 'initiator';
        state.role = myRole;

        const peerPubShare = Buffer.from(matched.pubShare!, 'base64url');
        const peerId = matched.id ?? '';
        const { channelId, encKey } = spake2Finish(state, peerPubShare, w, pairingId, this.id, peerId);

        // Join the channel
        this.sendRaw({
            type: 'join',
            ch: channelId,
            id: this.id,
            role: myRole,
        });

        // Challenge-response loop: handle re-challenges until verify_peer
        let verify: InMsg | undefined;
        const deadline = Date.now() + 30000;
        while (!verify) {
            const remaining = deadline - Date.now();
            if (remaining <= 0) throw new Error('Timed out waiting for verify_peer');

            // Wait for either challenge or verify_peer
            const msg = await this.waitForAny(
                [`challenge:${channelId}`, `verify_peer:${channelId}`],
                remaining,
            );

            if (msg.type === 'verify_peer') {
                verify = msg;
                break;
            }

            // Respond to challenge
            const nonce = Buffer.from(msg.nonce!, 'base64url');
            const mac = computeChallengeMac(encKey, channelId, nonce, this.id, myRole);
            this.sendRaw({
                type: 'response',
                ch: channelId,
                mac: mac.toString('base64url'),
                role: myRole,
            });
        }

        // Verify peer's MAC
        const peerNonce = Buffer.from(verify.peerNonce!, 'base64url');
        const peerMac = Buffer.from(verify.peerMac!, 'base64url');
        const peerIdFromVerify = verify.peerId ?? peerId;
        const peerRole = verify.peerRole ?? (myRole === 'initiator' ? 'responder' : 'initiator');
        const expectedMac = computeChallengeMac(encKey, channelId, peerNonce, peerIdFromVerify, peerRole);

        if (!crypto.timingSafeEqual(peerMac, expectedMac)) {
            this.sendRaw({ type: 'error', code: 'verify_rejected', ch: channelId });
            throw new Error('Peer verification failed: MAC mismatch');
        }

        const channelState: ChannelState = {
            channelId,
            encKey,
            role: myRole,
            peerId: peerIdFromVerify,
            active: true,
        };

        this.channels.set(channelId, channelState);
        return channelState;
    }

    async send(channelId: string, data: Buffer): Promise<void> {
        const ch = this.channels.get(channelId);
        if (!ch) throw new Error(`Unknown channel: ${channelId}`);

        const ciphertext = encrypt(ch.encKey, channelId, data);
        this.sendRaw({
            type: 'message',
            ch: channelId,
            data: ciphertext.toString('base64url'),
        });
    }

    async close(): Promise<void> {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}
