import Foundation
import CryptoKit

// MARK: - Wire protocol message types

/// OutMsg is what the client sends (outgoing to server).
struct OutMsg: Codable {
    var type: String
    var ch: String?
    var id: String?
    var pubShare: String? // base64url
    var mac: String?      // base64url
    var data: String?     // base64url
    var code: String?
    var role: String?
}

/// InMsg is what the client receives (incoming from server).
struct InMsg: Codable {
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
    private var continuations: [String: CheckedContinuation<InMsg, Error>] = [:]
    private var challengeContinuations: [String: CheckedContinuation<InMsg, Error>] = [:]
    private var verifyPeerContinuations: [String: CheckedContinuation<InMsg, Error>] = [:]
    private var pairContinuations: [String: CheckedContinuation<InMsg, Error>] = [:]
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
        let (current, previous) = try derivePairingParamsBothWindows(code: code)
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
        let pairMsg = OutMsg(
            type: "pair",
            ch: pairingId,
            id: id,
            pubShare: base64urlEncode(pubShare)
        )
        try await sendJSON(pairMsg)

        // Wait for pair_matched
        let matched: InMsg = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                self.lock.lock()
                self.pairContinuations[pairingId] = cont
                self.lock.unlock()
            }
        } onCancel: {
            self.lock.lock()
            let cont = self.pairContinuations.removeValue(forKey: pairingId)
            self.lock.unlock()
            cont?.resume(throwing: CancellationError())
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

        // Join the channel and run challenge-response flow
        return try await joinAndChallenge(channelId: channelId, encKey: encKey, role: role, expectedPeerId: peerId)
    }

    /// Join a channel and complete the challenge-response verification flow.
    /// Used by both pair() and rejoin().
    private func joinAndChallenge(channelId: String, encKey: SymmetricKey, role: String, expectedPeerId: String = "") async throws -> ChannelState {
        let joinMsg = OutMsg(type: "join", ch: channelId, id: id)
        try await sendJSON(joinMsg)

        // Challenge loop: wait for challenges and verify_peer.
        // Re-challenges can arrive when the second peer joins, so we loop
        // responding to each challenge until we receive verify_peer.
        // Both challenge and verify_peer continuations are registered before
        // each wait so no messages are dropped.
        let verify: InMsg = try await withTimeout(seconds: 30) {
            try await self.challengeLoop(channelId: channelId, encKey: encKey, role: role)
        }

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

        let actualPeerId = verify.peerId ?? expectedPeerId
        let peerRole = verify.peerRole ?? (role == "initiator" ? "responder" : "initiator")

        // Reject if peer has the same ID as us (self-pairing)
        if actualPeerId == id {
            let rejectMsg = OutMsg(type: "error", ch: channelId, code: "verify_rejected")
            try await sendJSON(rejectMsg)
            throw LatchRelayError.verifyRejected
        }

        let valid = verifyChallengeMAC(
            encKey: encKey, channelId: channelId,
            nonce: peerNonce, id: actualPeerId, role: peerRole, mac: peerMac
        )

        if !valid {
            let rejectMsg = OutMsg(type: "error", ch: channelId, code: "verify_rejected")
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
        lock.unlock()

        return state
    }

    /// Rejoin an existing channel after reconnection.
    public func rejoin(channelId: String, encKey: Data, role: String) async throws -> ChannelState {
        guard webSocket != nil else { throw LatchRelayError.connectionClosed }
        let symKey = SymmetricKey(data: encKey)
        return try await joinAndChallenge(channelId: channelId, encKey: symKey, role: role)
    }

    /// Challenge-response loop: waits for challenge/verify_peer messages,
    /// responds to challenges, returns verify_peer when received.
    /// Fixes the race condition by always registering the next challenge
    /// continuation before consuming the current one.
    private func challengeLoop(channelId: String, encKey: SymmetricKey, role: String) async throws -> InMsg {
        // Wait for initial challenge
        let challenge: InMsg = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                self.lock.lock()
                self.challengeContinuations[channelId] = cont
                self.lock.unlock()
            }
        } onCancel: {
            self.lock.lock()
            let cont = self.challengeContinuations.removeValue(forKey: channelId)
            self.lock.unlock()
            cont?.resume(throwing: CancellationError())
        }

        guard challenge.type == "challenge",
              let nonceB64 = challenge.nonce,
              var nonce = base64urlDecode(nonceB64) else {
            throw LatchRelayError.channelError("expected challenge")
        }

        // After receiving a challenge, respond and wait for verify_peer.
        // A re-challenge may arrive if we're the first peer and the second
        // peer joins after our initial challenge. We loop to handle this.
        while true {
            // Register re-challenge continuation BEFORE verify_peer and response,
            // so no re-challenge is dropped in between.
            let reChallengeTask = Task<InMsg, Error> {
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { cont in
                        self.lock.lock()
                        self.challengeContinuations[channelId] = cont
                        self.lock.unlock()
                    }
                } onCancel: {
                    self.lock.lock()
                    let cont = self.challengeContinuations.removeValue(forKey: channelId)
                    self.lock.unlock()
                    cont?.resume(throwing: CancellationError())
                }
            }

            let verifyTask = Task<InMsg, Error> {
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { cont in
                        self.lock.lock()
                        self.verifyPeerContinuations[channelId] = cont
                        self.lock.unlock()
                    }
                } onCancel: {
                    self.lock.lock()
                    let cont = self.verifyPeerContinuations.removeValue(forKey: channelId)
                    self.lock.unlock()
                    cont?.resume(throwing: CancellationError())
                }
            }

            // Respond to the current challenge
            let mac = computeChallengeMAC(encKey: encKey, channelId: channelId, nonce: nonce, id: id, role: role)
            let responseMsg = OutMsg(type: "response", ch: channelId, mac: base64urlEncode(mac))
            try await sendJSON(responseMsg)

            // Race: wait for verify_peer or re-challenge
            let result: InMsg = try await withThrowingTaskGroup(of: InMsg.self) { group in
                group.addTask { try await verifyTask.value }
                group.addTask { try await reChallengeTask.value }
                let first = try await group.next()!
                group.cancelAll()
                return first
            }

            if result.type == "verify_peer" {
                reChallengeTask.cancel()
                lock.lock()
                challengeContinuations.removeValue(forKey: channelId)
                lock.unlock()
                return result
            }

            // Got a re-challenge: update nonce for next iteration
            verifyTask.cancel()
            lock.lock()
            verifyPeerContinuations.removeValue(forKey: channelId)
            lock.unlock()

            guard let reNonceB64 = result.nonce,
                  let reNonce = base64urlDecode(reNonceB64) else {
                throw LatchRelayError.channelError("re-challenge missing nonce")
            }
            nonce = reNonce
        }
    }

    /// Run an async closure with a timeout.
    private func withTimeout<T>(seconds: TimeInterval, operation: @escaping () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                throw LatchRelayError.timeout
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
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
        let msg = OutMsg(type: "message", ch: channelId, data: base64urlEncode(encrypted))
        try await sendJSON(msg)
    }

    /// Send a plaintext string (encrypts it).
    public func send(channelId: String, text: String) async throws {
        try await send(channelId: channelId, data: text.data(using: .utf8)!)
    }

    /// Leave a channel.
    public func leave(channelId: String) async throws {
        let msg = OutMsg(type: "leave", ch: channelId)
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

    private func sendJSON(_ msg: OutMsg) async throws {
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
        guard let msg = try? decoder.decode(InMsg.self, from: data) else { return }

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

    private func handleReChallenge(_ msg: InMsg) {
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
        let responseMsg = OutMsg(type: "response", ch: ch, mac: base64urlEncode(mac))

        Task {
            try? await sendJSON(responseMsg)
        }
    }

    private func handleRelayedMessage(_ msg: InMsg) {
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
