import Foundation
import CryptoKit

// MARK: - Wire protocol message types

struct InMsg: Codable {
    var type: String
    var ch: String?
    var id: String?
    var pubShare: String? // base64url
    var mac: String?      // base64url
    var data: String?     // base64url
    var code: String?
    var role: String?
}

struct OutMsg: Codable {
    var type: String
    var ch: String?
    var pubShare: String?
    var id: String?
    var role: String?
    var nonce: String?
    var peerNonce: String?
    var peerMac: String?
    var peerId: String?
    var peerRole: String?
    var data: String?
    var code: String?
    var message: String?
}

// MARK: - Channel state

public struct ChannelState {
    public let channelId: String
    public let encKey: SymmetricKey
    public let role: String
    public let peerId: String
    public var active: Bool
}

// MARK: - LatchClient

public class LatchClient {
    public let serverURL: URL
    public let id: String
    public private(set) var channels: [String: ChannelState] = [:]
    public var onMessage: ((String, String, Data) -> Void)?
    public var onPeerLeft: ((String, String) -> Void)?
    public var onError: ((String, String) -> Void)?

    private var webSocket: URLSessionWebSocketTask?
    private let session: URLSession
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var continuations: [String: CheckedContinuation<OutMsg, Error>] = [:]
    private var challengeContinuations: [String: CheckedContinuation<OutMsg, Error>] = [:]
    private var verifyPeerContinuations: [String: CheckedContinuation<OutMsg, Error>] = [:]
    private var pairContinuations: [String: CheckedContinuation<OutMsg, Error>] = [:]
    private let lock = NSLock()
    private var receiveTask: Task<Void, Never>?

    public init(serverURL: URL, id: String) {
        self.serverURL = serverURL
        self.id = id
        self.session = URLSession(configuration: .default)
    }

    /// Connect to the relay server via WebSocket.
    public func connect() async throws {
        let wsURL: URL
        if serverURL.scheme == "http" {
            var components = URLComponents(url: serverURL, resolvingAgainstBaseURL: false)!
            components.scheme = "ws"
            wsURL = components.url!
        } else if serverURL.scheme == "https" {
            var components = URLComponents(url: serverURL, resolvingAgainstBaseURL: false)!
            components.scheme = "wss"
            wsURL = components.url!
        } else {
            wsURL = serverURL
        }

        let connectURL: URL
        if wsURL.path.hasSuffix("/v1/connect") {
            connectURL = wsURL
        } else {
            connectURL = wsURL.appendingPathComponent("v1/connect")
        }

        webSocket = session.webSocketTask(with: connectURL)
        webSocket?.resume()

        receiveTask = Task { [weak self] in
            await self?.receiveLoop()
        }
    }

    /// Pair with another client using a pairing code.
    /// Returns the channel state after successful SPAKE2 key agreement and channel establishment.
    public func pair(code: String) async throws -> ChannelState {
        guard webSocket != nil else { throw LatchRelayError.connectionClosed }
        let (current, previous) = derivePairingParamsBothWindows(code: code)
        do {
            return try await pairWithParams(pairingId: current.pairingId, w: current.w)
        } catch LatchRelayError.timeout {
            return try await pairWithParams(pairingId: previous.pairingId, w: previous.w)
        }
    }

    /// Internal pairing implementation using specific pairing parameters.
    private func pairWithParams(pairingId: String, w: BigUInt256) async throws -> ChannelState {
        // Start SPAKE2 (both peers blind with M, role assigned later)
        let (scalar, pubShare) = spake2Start(w: w)

        // Send pair message
        let pairMsg = InMsg(
            type: "pair",
            ch: pairingId,
            id: id,
            pubShare: base64urlEncode(pubShare)
        )
        try await sendJSON(pairMsg)

        // Wait for pair_matched
        let matched: OutMsg = try await withCheckedThrowingContinuation { cont in
            lock.lock()
            pairContinuations[pairingId] = cont
            lock.unlock()
        }

        guard matched.type == "pair_matched" else {
            throw LatchRelayError.pairingFailed(matched.message ?? "unexpected response")
        }

        let role = matched.role ?? "initiator"
        let peerId = matched.id ?? ""
        guard let peerPubShareB64 = matched.pubShare,
              let peerPubShare = base64urlDecode(peerPubShareB64) else {
            throw LatchRelayError.pairingFailed("missing peer pubShare")
        }

        // Complete SPAKE2 (both peers blinded with M, finish removes w*M)
        let (channelId, encKey): (String, SymmetricKey)
        if role == "initiator" {
            (channelId, encKey) = try spake2InitiatorFinish(
                x: scalar, w: w, peerPubShare: peerPubShare,
                myPubShare: pubShare, pairingId: pairingId,
                myId: id, peerId: peerId
            )
        } else {
            (channelId, encKey) = try spake2ResponderFinish(
                y: scalar, w: w, peerPubShare: peerPubShare,
                myPubShare: pubShare, pairingId: pairingId,
                myId: id, peerId: peerId
            )
        }

        // Join the channel
        let joinMsg = InMsg(type: "join", ch: channelId, id: id)
        try await sendJSON(joinMsg)

        // Wait for challenge
        let challenge: OutMsg = try await withCheckedThrowingContinuation { cont in
            lock.lock()
            challengeContinuations[channelId] = cont
            lock.unlock()
        }

        guard challenge.type == "challenge",
              let nonceB64 = challenge.nonce,
              let nonce = base64urlDecode(nonceB64) else {
            throw LatchRelayError.channelError("expected challenge")
        }

        // We might get re-challenged when the second peer joins.
        // Register for the next challenge/verify_peer before responding.
        // Actually, the protocol flow is:
        // 1. First peer joins -> gets challenge (WAIT_PEER state)
        // 2. Second peer joins -> both get fresh challenges
        // 3. Both respond
        // 4. Both get verify_peer

        // We need to handle the re-challenge case. If we're the first to join,
        // we'll get a challenge, then when the peer joins we get another challenge.
        // Let's wait for the final challenge by also registering for the next one.

        // Send response with initial challenge nonce first
        // Actually, we might get re-challenged. Let's handle both cases.
        // Register verify_peer continuation now.
        let verifyPromise: Task<OutMsg, Error> = Task {
            try await withCheckedThrowingContinuation { cont in
                self.lock.lock()
                self.verifyPeerContinuations[channelId] = cont
                self.lock.unlock()
            }
        }

        // We might get a re-challenge. Let's also listen for that.
        // Register another challenge continuation
        let reChallengeTask: Task<OutMsg?, Error> = Task {
            try await withCheckedThrowingContinuation { cont in
                self.lock.lock()
                self.challengeContinuations[channelId] = cont
                self.lock.unlock()
            }
        }

        // Compute and send MAC for the first challenge
        let mac = computeChallengeMAC(encKey: encKey, channelId: channelId, nonce: nonce, id: id, role: role)
        let responseMsg = InMsg(type: "response", ch: channelId, mac: base64urlEncode(mac))
        try await sendJSON(responseMsg)

        // Wait for either verify_peer or re-challenge
        // The verify_peer task or the re-challenge task will complete.
        // We use a simple approach: check if we get a re-challenge within a short window.

        // Actually, let's simplify. We'll handle re-challenges in the receive loop
        // by updating the challenge continuation. The verify_peer continuation
        // is what we truly wait for.

        // Wait for verify_peer (might be preceded by re-challenge handled in receive loop)
        let verify = try await verifyPromise.value

        guard verify.type == "verify_peer" else {
            throw LatchRelayError.channelError("expected verify_peer")
        }

        // Verify peer's MAC
        guard let peerNonceB64 = verify.peerNonce,
              let peerNonce = base64urlDecode(peerNonceB64),
              let peerMacB64 = verify.peerMac,
              let peerMac = base64urlDecode(peerMacB64) else {
            throw LatchRelayError.channelError("missing verify_peer fields")
        }

        let actualPeerId = verify.peerId ?? peerId
        let peerRole = verify.peerRole ?? (role == "initiator" ? "responder" : "initiator")

        // Reject if peer has the same ID as us (self-pairing)
        if actualPeerId == id {
            let rejectMsg = InMsg(type: "error", ch: channelId, code: "verify_rejected")
            try await sendJSON(rejectMsg)
            throw LatchRelayError.verifyRejected
        }

        let valid = verifyChallengeMAC(
            encKey: encKey, channelId: channelId,
            nonce: peerNonce, id: actualPeerId, role: peerRole, mac: peerMac
        )

        if !valid {
            // Send verify_rejected
            let rejectMsg = InMsg(type: "error", ch: channelId, code: "verify_rejected")
            try await sendJSON(rejectMsg)
            throw LatchRelayError.verifyRejected
        }

        let state = ChannelState(
            channelId: channelId,
            encKey: encKey,
            role: role,
            peerId: actualPeerId,
            active: true
        )
        lock.lock()
        channels[channelId] = state
        // Cancel the re-challenge task if still pending
        reChallengeTask.cancel()
        lock.unlock()

        return state
    }

    /// Send encrypted data on a channel.
    public func send(channelId: String, data: Data) async throws {
        guard let channel = channels[channelId] else {
            throw LatchRelayError.channelError("channel not found")
        }
        guard channel.active else {
            throw LatchRelayError.channelError("channel not active")
        }

        let aad = channelId.data(using: .utf8)!
        let encrypted = try aesGCMEncrypt(plaintext: data, key: channel.encKey, aad: aad)
        let msg = InMsg(type: "message", ch: channelId, data: base64urlEncode(encrypted))
        try await sendJSON(msg)
    }

    /// Send a plaintext string (encrypts it).
    public func send(channelId: String, text: String) async throws {
        try await send(channelId: channelId, data: text.data(using: .utf8)!)
    }

    /// Leave a channel.
    public func leave(channelId: String) async throws {
        let msg = InMsg(type: "leave", ch: channelId)
        try await sendJSON(msg)
        lock.lock()
        channels[channelId]?.active = false
        lock.unlock()
    }

    /// Close the WebSocket connection.
    public func close() {
        receiveTask?.cancel()
        webSocket?.cancel(with: .normalClosure, reason: nil)
        webSocket = nil
    }

    // MARK: - Private

    private func sendJSON(_ msg: InMsg) async throws {
        guard let ws = webSocket else { throw LatchRelayError.connectionClosed }
        let data = try encoder.encode(msg)
        try await ws.send(.string(String(data: data, encoding: .utf8)!))
    }

    private func receiveLoop() async {
        guard let ws = webSocket else { return }
        while !Task.isCancelled {
            do {
                let message = try await ws.receive()
                switch message {
                case .string(let text):
                    guard let data = text.data(using: .utf8) else { continue }
                    handleMessage(data)
                case .data(let data):
                    handleMessage(data)
                @unknown default:
                    continue
                }
            } catch {
                // Connection closed or error
                return
            }
        }
    }

    private func handleMessage(_ data: Data) {
        guard let msg = try? decoder.decode(OutMsg.self, from: data) else { return }

        switch msg.type {
        case "pair_matched":
            lock.lock()
            let cont = pairContinuations.removeValue(forKey: msg.ch ?? "")
            lock.unlock()
            cont?.resume(returning: msg)

        case "challenge":
            let ch = msg.ch ?? ""
            lock.lock()
            let cont = challengeContinuations.removeValue(forKey: ch)
            lock.unlock()
            if let cont = cont {
                cont.resume(returning: msg)
            } else {
                // Re-challenge: we need to re-respond
                handleReChallenge(msg)
            }

        case "verify_peer":
            lock.lock()
            let cont = verifyPeerContinuations.removeValue(forKey: msg.ch ?? "")
            lock.unlock()
            cont?.resume(returning: msg)

        case "message":
            handleRelayedMessage(msg)

        case "peer_left":
            let ch = msg.ch ?? ""
            lock.lock()
            channels[ch]?.active = false
            lock.unlock()
            onPeerLeft?(ch, msg.peerId ?? "")

        case "error":
            let ch = msg.ch ?? ""
            let code = msg.code ?? ""

            // Resume any waiting continuations with error
            lock.lock()
            let pairCont = pairContinuations.removeValue(forKey: ch)
            let challengeCont = challengeContinuations.removeValue(forKey: ch)
            let verifyCont = verifyPeerContinuations.removeValue(forKey: ch)
            lock.unlock()

            let error = LatchRelayError.channelError(code)
            pairCont?.resume(throwing: error)
            challengeCont?.resume(throwing: error)
            verifyCont?.resume(throwing: error)

            onError?(ch, code)

        default:
            break
        }
    }

    private func handleReChallenge(_ msg: OutMsg) {
        // During pairing, we might receive a re-challenge after sending our initial response.
        // We need to compute a new MAC and send a new response.
        let ch = msg.ch ?? ""
        guard let channel = channels[ch] ?? nil else {
            // Channel not yet fully established - this happens during pairing.
            // We need the encKey, which we may not have stored yet.
            // The pair() method handles this via the continuation pattern.
            // If we get here, it means we got a re-challenge while pair() is still running.
            // The challenge continuation should have been set up.
            // Actually this shouldn't happen because pair() registers a new
            // challengeContinuation before sending the response.
            return
        }

        guard let nonceB64 = msg.nonce,
              let nonce = base64urlDecode(nonceB64) else { return }

        let mac = computeChallengeMAC(
            encKey: channel.encKey, channelId: ch,
            nonce: nonce, id: id, role: channel.role
        )
        let responseMsg = InMsg(type: "response", ch: ch, mac: base64urlEncode(mac))

        Task {
            try? await sendJSON(responseMsg)
        }
    }

    private func handleRelayedMessage(_ msg: OutMsg) {
        let ch = msg.ch ?? ""
        guard let channel = channels[ch],
              let dataB64 = msg.data,
              let ciphertext = base64urlDecode(dataB64) else { return }

        let aad = ch.data(using: .utf8)!
        guard let plaintext = try? aesGCMDecrypt(ciphertext: ciphertext, key: channel.encKey, aad: aad) else {
            return
        }

        onMessage?(ch, msg.peerId ?? "", plaintext)
    }
}
