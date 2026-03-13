import {
    derivePairingParamsBothWindows,
    spake2Start,
    spake2Finish,
    computeChallengeMac,
    encrypt,
    decrypt,
    toBase64url,
    fromBase64url,
    timingSafeEqual,
} from './crypto.js';

export interface ChannelState {
    channelId: string;
    encKey: Uint8Array;
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

    onMessage?: (channelId: string, peerId: string, data: Uint8Array) => void;

    constructor(serverUrl: string, id: string) {
        this.serverUrl = serverUrl;
        this.id = id;
    }

    async connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.serverUrl);
            this.ws.onopen = () => resolve();
            this.ws.onerror = () => reject(new Error('WebSocket connection failed'));
            this.ws.onmessage = (event) => {
                let msg: InMsg;
                try {
                    msg = JSON.parse(event.data as string);
                } catch {
                    console.error('latch-relay: failed to parse message');
                    return;
                }
                this.dispatch(msg);
            };
        });
    }

    private async dispatch(msg: InMsg): Promise<void> {
        // Handle relayed messages
        if (msg.type === 'message' && msg.ch && msg.data) {
            const ch = this.channels.get(msg.ch);
            if (ch && this.onMessage) {
                const ciphertext = fromBase64url(msg.data);
                try {
                    const plaintext = await decrypt(ch.encKey, ch.channelId, ciphertext);
                    this.onMessage(ch.channelId, msg.peerId ?? '', plaintext);
                } catch {
                    // Ignore decryption failures
                }
            }
            return;
        }

        // Handle peer_left
        if (msg.type === 'peer_left' && msg.ch) {
            const ch = this.channels.get(msg.ch);
            if (ch) ch.active = false;
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
            const resolver: Resolver = (msg) => {
                clearTimeout(timer);
                resolve(msg);
            };
            const timer = setTimeout(() => {
                const list = this.waiters.get(key);
                if (list) {
                    const idx = list.indexOf(resolver);
                    if (idx >= 0) list.splice(idx, 1);
                }
                reject(new Error(`timeout waiting for ${key}`));
            }, timeoutMs);
            if (!this.waiters.has(key)) {
                this.waiters.set(key, []);
            }
            this.waiters.get(key)!.push(resolver);
        });
    }

    private waitForAny(keys: string[], timeoutMs = 30000): Promise<InMsg> {
        return new Promise((resolve, reject) => {
            let resolved = false;

            const resolver: Resolver = (msg) => {
                if (resolved) return;
                resolved = true;
                clearTimeout(timer);
                for (const k of keys) {
                    const list = this.waiters.get(k);
                    if (list) {
                        const idx = list.indexOf(resolver);
                        if (idx >= 0) list.splice(idx, 1);
                    }
                }
                resolve(msg);
            };

            const timer = setTimeout(() => {
                if (resolved) return;
                resolved = true;
                for (const k of keys) {
                    const list = this.waiters.get(k);
                    if (list) {
                        const idx = list.indexOf(resolver);
                        if (idx >= 0) list.splice(idx, 1);
                    }
                }
                reject(new Error(`timeout waiting for ${keys.join('|')}`));
            }, timeoutMs);

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
        const { current, previous } = await derivePairingParamsBothWindows(code);
        try {
            return await this.pairWithParams(current.pairingId, current.w);
        } catch (e) {
            if (e instanceof Error && (e.message.includes('timeout') || e.message.includes('closed'))) {
                return await this.pairWithParams(previous.pairingId, previous.w);
            }
            throw e;
        }
    }

    private async pairWithParams(pairingId: string, w: bigint): Promise<ChannelState> {
        const state = spake2Start(w, 'initiator');

        this.sendRaw({
            type: 'pair',
            ch: pairingId,
            id: this.id,
            pubShare: toBase64url(state.pubShare),
        });

        const matched = await this.waitFor(`pair_matched:${pairingId}`);
        const myRole = (matched.role as 'initiator' | 'responder') ?? 'initiator';
        state.role = myRole;

        const peerPubShare = fromBase64url(matched.pubShare!);
        const peerId = matched.id ?? '';
        const { channelId, encKey } = await spake2Finish(state, peerPubShare, w, pairingId, this.id, peerId);

        this.sendRaw({
            type: 'join',
            ch: channelId,
            id: this.id,
        });

        // Challenge-response loop
        let verify: InMsg | undefined;
        const deadline = Date.now() + 30000;
        while (!verify) {
            const remaining = deadline - Date.now();
            if (remaining <= 0) throw new Error('Timed out waiting for verify_peer');

            const msg = await this.waitForAny(
                [`challenge:${channelId}`, `verify_peer:${channelId}`],
                remaining,
            );

            if (msg.type === 'verify_peer') {
                verify = msg;
                break;
            }

            const nonce = fromBase64url(msg.nonce!);
            const mac = await computeChallengeMac(encKey, channelId, nonce, this.id, myRole);
            this.sendRaw({
                type: 'response',
                ch: channelId,
                mac: toBase64url(mac),
            });
        }

        // Verify peer's MAC
        const peerNonce = fromBase64url(verify.peerNonce!);
        const peerMac = fromBase64url(verify.peerMac!);
        const peerIdFromVerify = verify.peerId ?? peerId;
        const peerRole = verify.peerRole ?? (myRole === 'initiator' ? 'responder' : 'initiator');
        const expectedMac = await computeChallengeMac(encKey, channelId, peerNonce, peerIdFromVerify, peerRole);

        if (peerIdFromVerify === this.id) {
            this.sendRaw({ type: 'error', code: 'verify_rejected', ch: channelId });
            throw new Error('Peer verification failed: peerId equals own id (possible reflection)');
        }

        if (!timingSafeEqual(peerMac, expectedMac)) {
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

    async rejoin(channelId: string, encKey: Uint8Array, role: 'initiator' | 'responder'): Promise<ChannelState> {
        this.sendRaw({
            type: 'join',
            ch: channelId,
            id: this.id,
        });

        // Challenge-response loop
        let verify: InMsg | undefined;
        const deadline = Date.now() + 30000;
        while (!verify) {
            const remaining = deadline - Date.now();
            if (remaining <= 0) throw new Error('Timed out waiting for verify_peer');

            const msg = await this.waitForAny(
                [`challenge:${channelId}`, `verify_peer:${channelId}`],
                remaining,
            );

            if (msg.type === 'verify_peer') {
                verify = msg;
                break;
            }

            const nonce = fromBase64url(msg.nonce!);
            const mac = await computeChallengeMac(encKey, channelId, nonce, this.id, role);
            this.sendRaw({
                type: 'response',
                ch: channelId,
                mac: toBase64url(mac),
            });
        }

        // Verify peer's MAC
        const peerNonce = fromBase64url(verify.peerNonce!);
        const peerMac = fromBase64url(verify.peerMac!);
        const peerId = verify.peerId ?? '';
        const peerRole = verify.peerRole ?? (role === 'initiator' ? 'responder' : 'initiator');
        const expectedMac = await computeChallengeMac(encKey, channelId, peerNonce, peerId, peerRole);

        if (peerId === this.id) {
            this.sendRaw({ type: 'error', code: 'verify_rejected', ch: channelId });
            throw new Error('Peer verification failed: peerId equals own id (possible reflection)');
        }

        if (!timingSafeEqual(peerMac, expectedMac)) {
            this.sendRaw({ type: 'error', code: 'verify_rejected', ch: channelId });
            throw new Error('Peer verification failed: MAC mismatch');
        }

        const channelState: ChannelState = {
            channelId,
            encKey,
            role,
            peerId,
            active: true,
        };

        this.channels.set(channelId, channelState);
        return channelState;
    }

    async send(channelId: string, data: Uint8Array): Promise<void> {
        const ch = this.channels.get(channelId);
        if (!ch) throw new Error(`Unknown channel: ${channelId}`);

        const ciphertext = await encrypt(ch.encKey, channelId, data);
        this.sendRaw({
            type: 'message',
            ch: channelId,
            data: toBase64url(ciphertext),
        });
    }

    async close(): Promise<void> {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}
