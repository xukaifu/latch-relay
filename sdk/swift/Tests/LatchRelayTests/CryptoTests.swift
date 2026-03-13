import XCTest
import CryptoKit
@testable import LatchRelay

final class CryptoTests: XCTestCase {

    // MARK: - BigUInt256

    func testBigUInt256FromData() {
        let data = Data(hexString: "0000000000000000000000000000000000000000000000000000000000000001")!
        let n = BigUInt256(data: data)
        XCTAssertEqual(n, BigUInt256.one)
    }

    func testBigUInt256RoundTrip() {
        let original = Data(hexString: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")!
        let n = BigUInt256(data: original)
        XCTAssertEqual(n.data.hexString, original.hexString.lowercased())
    }

    func testBigUInt256Comparison() {
        let a = BigUInt256(w: (1, 0, 0, 0))
        let b = BigUInt256(w: (2, 0, 0, 0))
        XCTAssertTrue(a < b)
        XCTAssertFalse(b < a)
        XCTAssertTrue(a == a)
    }

    // MARK: - Modular Arithmetic

    func testModAdd() {
        let p = ModP256.p
        let pMinus1 = bigSub(p, BigUInt256.one).0
        let result = ModP256.add(pMinus1, BigUInt256.one)
        XCTAssertEqual(result, BigUInt256.zero)
    }

    func testModSub() {
        let result = ModP256.sub(BigUInt256.zero, BigUInt256.one)
        let expected = bigSub(ModP256.p, BigUInt256.one).0
        XCTAssertEqual(result, expected)
    }

    func testModMul() {
        let two = BigUInt256(w: (2, 0, 0, 0))
        let three = BigUInt256(w: (3, 0, 0, 0))
        let result = ModP256.mul(two, three)
        XCTAssertEqual(result, BigUInt256(w: (6, 0, 0, 0)))
    }

    func testModInv() {
        let two = BigUInt256(w: (2, 0, 0, 0))
        let inv2 = ModP256.inv(two)
        let product = ModP256.mul(two, inv2)
        XCTAssertEqual(product, BigUInt256.one)
    }

    // MARK: - P-256 Point Operations

    func testGeneratorPointOnCurve() {
        // Verify G is on the curve: y^2 = x^3 + ax + b
        let gx = BigUInt256(data: Data(hexString: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!)
        let gy = BigUInt256(data: Data(hexString: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")!)

        let y2 = ModP256.sqr(gy)
        let x3 = ModP256.mul(ModP256.sqr(gx), gx)
        let ax = ModP256.mul(ModP256.sub(ModP256.p, BigUInt256(w: (3, 0, 0, 0))), gx)
        let rhs = ModP256.add(ModP256.add(x3, ax), ModP256.b)

        XCTAssertEqual(y2, rhs, "Generator point should be on the P-256 curve")
    }

    func testPointDecompression() throws {
        // Decompress M point
        let mData = Data(hexString: "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")!
        let m = try P256Point(compressed: mData)

        // Verify it's on the curve
        let (mx, my) = m.affine()
        let y2 = ModP256.sqr(my)
        let x3 = ModP256.mul(ModP256.sqr(mx), mx)
        let ax = ModP256.mul(ModP256.sub(ModP256.p, BigUInt256(w: (3, 0, 0, 0))), mx)
        let rhs = ModP256.add(ModP256.add(x3, ax), ModP256.b)
        XCTAssertEqual(y2, rhs, "M point should be on the curve")

        // Verify x matches
        let expectedX = BigUInt256(data: Data(hexString: "886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")!)
        XCTAssertEqual(mx, expectedX)

        // Verify even y (prefix 0x02)
        XCTAssertEqual(my[0] & 1, 0, "M point should have even y")
    }

    func testPointAdditionIdentity() {
        let g = P256Point(
            x: BigUInt256(data: Data(hexString: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!),
            y: BigUInt256(data: Data(hexString: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")!),
            z: .one
        )
        let result = P256Point.add(.infinity, g)
        let (rx, ry) = result.affine()
        let (gx, gy) = g.affine()
        XCTAssertEqual(rx, gx)
        XCTAssertEqual(ry, gy)
    }

    func testScalarMulByOne() {
        let g = P256Point(
            x: BigUInt256(data: Data(hexString: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!),
            y: BigUInt256(data: Data(hexString: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")!),
            z: .one
        )
        let result = P256Point.mul(.one, g)
        let (rx, ry) = result.affine()
        let (gx, gy) = g.affine()
        XCTAssertEqual(rx, gx)
        XCTAssertEqual(ry, gy)
    }

    func testScalarMulByOrder() {
        // n * G = infinity
        let g = P256Point(
            x: BigUInt256(data: Data(hexString: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!),
            y: BigUInt256(data: Data(hexString: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")!),
            z: .one
        )
        let result = P256Point.mul(ModP256.n, g)
        XCTAssertTrue(result.isInfinity, "n * G should be the point at infinity")
    }

    func testUncompressedRoundTrip() throws {
        let g = P256Point(
            x: BigUInt256(data: Data(hexString: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!),
            y: BigUInt256(data: Data(hexString: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")!),
            z: .one
        )
        let data = g.toUncompressed()
        XCTAssertEqual(data.count, 65)
        XCTAssertEqual(data[0], 0x04)

        let recovered = try P256Point(uncompressed: data)
        let (gx, gy) = g.affine()
        let (rx, ry) = recovered.affine()
        XCTAssertEqual(gx, rx)
        XCTAssertEqual(gy, ry)
    }

    // MARK: - SPAKE2 Key Agreement

    func testSPAKE2KeyAgreement() throws {
        // Two parties perform SPAKE2 and should derive the same key
        let code = "TESTCODE"
        let (pairingId, w) = derivePairingParams(code: code)

        // Both peers blind with M (pubShare sent before role assignment)
        let (x, pA) = spake2Start(w: w)
        let (y, pB) = spake2Start(w: w)

        // Initiator finish
        let (channelIdI, encKeyI) = try spake2InitiatorFinish(
            x: x, w: w, peerPubShare: pB,
            myPubShare: pA, pairingId: pairingId
        )

        // Responder finish
        let (channelIdR, encKeyR) = try spake2ResponderFinish(
            y: y, w: w, peerPubShare: pA,
            myPubShare: pB, pairingId: pairingId
        )

        XCTAssertEqual(channelIdI, channelIdR, "Both sides should derive the same channel ID")

        // Compare keys by encrypting/decrypting
        let testData = "hello".data(using: .utf8)!
        let aad = channelIdI.data(using: .utf8)!
        let encrypted = try aesGCMEncrypt(plaintext: testData, key: encKeyI, aad: aad)
        let decrypted = try aesGCMDecrypt(ciphertext: encrypted, key: encKeyR, aad: aad)
        XCTAssertEqual(testData, decrypted, "Keys should be compatible for encryption")
    }

    // MARK: - PBKDF2

    func testPBKDF2() {
        let result = pbkdf2SHA256(password: "password", salt: "salt".data(using: .utf8)!, iterations: 1, keyLength: 32)
        XCTAssertEqual(result.count, 32)
        // Known test vector for PBKDF2-SHA256("password", "salt", 1, 32):
        // 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
        XCTAssertEqual(result.hexString, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    }

    // MARK: - HKDF

    func testHKDFExpand() {
        let prk = Data(repeating: 0x07, count: 32)
        let info = "test".data(using: .utf8)!
        let okm = hkdfExpandSHA256(prk: prk, info: info, length: 32)
        XCTAssertEqual(okm.count, 32)

        // Same input should produce same output
        let okm2 = hkdfExpandSHA256(prk: prk, info: info, length: 32)
        XCTAssertEqual(okm, okm2)

        // Different info should produce different output
        let okm3 = hkdfExpandSHA256(prk: prk, info: "other".data(using: .utf8)!, length: 32)
        XCTAssertNotEqual(okm, okm3)
    }

    // MARK: - HMAC Challenge-Response

    func testChallengeMAC() {
        let key = SymmetricKey(data: Data(repeating: 0xAB, count: 32))
        let nonce = Data(repeating: 0x01, count: 32)

        let mac1 = computeChallengeMAC(encKey: key, channelId: "ch1", nonce: nonce, id: "peer-A", role: "initiator")
        XCTAssertEqual(mac1.count, 32)

        // Same inputs -> same MAC
        let mac2 = computeChallengeMAC(encKey: key, channelId: "ch1", nonce: nonce, id: "peer-A", role: "initiator")
        XCTAssertEqual(mac1, mac2)

        // Different inputs -> different MAC
        let mac3 = computeChallengeMAC(encKey: key, channelId: "ch1", nonce: nonce, id: "peer-B", role: "initiator")
        XCTAssertNotEqual(mac1, mac3)

        // Verify should pass
        XCTAssertTrue(verifyChallengeMAC(encKey: key, channelId: "ch1", nonce: nonce, id: "peer-A", role: "initiator", mac: mac1))

        // Verify should fail with wrong mac
        XCTAssertFalse(verifyChallengeMAC(encKey: key, channelId: "ch1", nonce: nonce, id: "peer-A", role: "initiator", mac: Data(repeating: 0, count: 32)))
    }

    // MARK: - AES-GCM

    func testAESGCMRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = "Hello, World!".data(using: .utf8)!
        let aad = "channel-id".data(using: .utf8)!

        let ciphertext = try aesGCMEncrypt(plaintext: plaintext, key: key, aad: aad)
        XCTAssertEqual(ciphertext.count, 12 + plaintext.count + 16) // nonce + ct + tag

        let decrypted = try aesGCMDecrypt(ciphertext: ciphertext, key: key, aad: aad)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAESGCMWrongKeyFails() throws {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let plaintext = "secret".data(using: .utf8)!
        let aad = "ch".data(using: .utf8)!

        let ciphertext = try aesGCMEncrypt(plaintext: plaintext, key: key1, aad: aad)
        XCTAssertThrowsError(try aesGCMDecrypt(ciphertext: ciphertext, key: key2, aad: aad))
    }

    func testAESGCMWrongAADFails() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = "secret".data(using: .utf8)!

        let ciphertext = try aesGCMEncrypt(plaintext: plaintext, key: key, aad: "aad1".data(using: .utf8)!)
        XCTAssertThrowsError(try aesGCMDecrypt(ciphertext: ciphertext, key: key, aad: "aad2".data(using: .utf8)!))
    }

    // MARK: - Base64url

    func testBase64urlRoundTrip() {
        let data = Data([0xFF, 0xFE, 0xFD, 0x00, 0x01])
        let encoded = base64urlEncode(data)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))

        let decoded = base64urlDecode(encoded)
        XCTAssertEqual(decoded, data)
    }

    func testBase64urlEmpty() {
        let encoded = base64urlEncode(Data())
        XCTAssertEqual(encoded, "")
        XCTAssertEqual(base64urlDecode(""), Data())
    }

    // MARK: - Pairing params determinism

    func testPairingParamsDeterministic() {
        let (id1, w1) = derivePairingParams(code: "ABC123")
        let (id2, w2) = derivePairingParams(code: "ABC123")
        XCTAssertEqual(id1, id2)
        XCTAssertEqual(w1, w2)

        // Case insensitive
        let (id3, w3) = derivePairingParams(code: "abc123")
        XCTAssertEqual(id1, id3)
        XCTAssertEqual(w1, w3)
    }

    func testPairingParamsDifferentCodes() {
        let (id1, _) = derivePairingParams(code: "CODE1")
        let (id2, _) = derivePairingParams(code: "CODE2")
        XCTAssertNotEqual(id1, id2)
    }
}
