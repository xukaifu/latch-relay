import XCTest
@testable import LatchRelay

final class ClientTests: XCTestCase {
    // Client tests require a running server.
    // These are skipped unless LATCH_RELAY_URL is set.

    var serverURL: URL? {
        guard let urlStr = ProcessInfo.processInfo.environment["LATCH_RELAY_URL"] else {
            return nil
        }
        return URL(string: urlStr)
    }

    func testClientConnectAndDisconnect() async throws {
        guard let url = serverURL else {
            throw XCTSkip("LATCH_RELAY_URL not set")
        }

        let client = LatchClient(serverURL: url, id: "test-peer")
        try await client.connect()
        await client.close()
    }

    func testTwoClientsPairAndExchange() async throws {
        guard let url = serverURL else {
            throw XCTSkip("LATCH_RELAY_URL not set")
        }

        let code = "TESTCODE\(Int.random(in: 100000...999999))"

        let client1 = LatchClient(serverURL: url, id: "peer-A")
        let client2 = LatchClient(serverURL: url, id: "peer-B")

        try await client1.connect()
        try await client2.connect()

        let expectation = XCTestExpectation(description: "message received")
        var receivedMessage: String?

        client2.onMessage = { channelId, peerId, data in
            receivedMessage = String(data: data, encoding: .utf8)
            expectation.fulfill()
        }

        // Pair concurrently
        async let channel1 = client1.pair(code: code)
        async let channel2 = client2.pair(code: code)

        let ch1 = try await channel1
        let ch2 = try await channel2

        XCTAssertEqual(ch1.channelId, ch2.channelId)
        XCTAssertTrue(ch1.active)
        XCTAssertTrue(ch2.active)

        // Send message
        try await client1.send(channelId: ch1.channelId, text: "hello from A")

        await fulfillment(of: [expectation], timeout: 5.0)
        XCTAssertEqual(receivedMessage, "hello from A")

        await client1.close()
        await client2.close()
    }
}
