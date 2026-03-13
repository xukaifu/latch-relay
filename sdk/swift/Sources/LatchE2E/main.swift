import Foundation
import LatchRelay

// Usage: latch-e2e --server URL --id PEER_ID --code CODE [--send MESSAGE]

func parseArgs() -> (server: String, id: String, code: String, message: String?) {
    let args = CommandLine.arguments
    var server = ""
    var id = ""
    var code = ""
    var message: String? = nil

    var i = 1
    while i < args.count {
        switch args[i] {
        case "--server":
            i += 1; server = args[i]
        case "--id":
            i += 1; id = args[i]
        case "--code":
            i += 1; code = args[i]
        case "--send":
            i += 1; message = args[i]
        default:
            break
        }
        i += 1
    }

    guard !server.isEmpty, !id.isEmpty, !code.isEmpty else {
        fputs("Usage: latch-e2e --server URL --id PEER_ID --code CODE [--send MESSAGE]\n", stderr)
        exit(1)
    }

    return (server, id, code, message)
}

func run() async throws {
    let (server, id, code, message) = parseArgs()

    guard let url = URL(string: server) else {
        fputs("Invalid server URL: \(server)\n", stderr)
        exit(1)
    }

    let client = LatchClient(serverURL: url, id: id)
    let sendMode = message != nil

    let receivedSemaphore = DispatchSemaphore(value: 0)
    client.onMessage = { channelId, peerId, data in
        // Output JSON to stdout for E2E test parsing
        let b64 = data.base64EncodedString()
        print("{\"from\":\"\(peerId)\",\"data\":\"\(b64)\"}")
        fflush(stdout)
        if sendMode {
            fputs("Received response, exiting\n", stderr)
            receivedSemaphore.signal()
        }
    }

    client.onPeerLeft = { channelId, peerId in
        fputs("[\(channelId)] peer \(peerId) left\n", stderr)
    }

    client.onError = { channelId, code in
        fputs("[\(channelId)] error: \(code)\n", stderr)
    }

    fputs("Connecting to \(server)...\n", stderr)
    try await client.connect()
    fputs("Connected as \(id)\n", stderr)

    fputs("Pairing with code \(code)...\n", stderr)
    let channel = try await client.pair(code: code)
    fputs("Paired! channelId=\(channel.channelId) role=\(channel.role) peer=\(channel.peerId)\n", stderr)

    if let message = message {
        fputs("Sending: \(message)\n", stderr)
        try await client.send(channelId: channel.channelId, text: message)
        fputs("Sent.\n", stderr)

        // Wait for response then exit
        receivedSemaphore.wait()
        // Small delay to ensure stdout is flushed
        try await Task.sleep(for: .milliseconds(100))
        client.close()
        exit(0)
    }

    // Keep running to receive messages
    fputs("Listening for messages...\n", stderr)
    try await Task.sleep(for: .seconds(300))

    client.close()
}

Task {
    do {
        try await run()
    } catch {
        fputs("Error: \(error)\n", stderr)
        exit(1)
    }
}

RunLoop.main.run()
