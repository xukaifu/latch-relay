import Foundation
import CryptoKit
#if canImport(CommonCrypto)
import CommonCrypto
#endif

// MARK: - Big Integer (mod p) for P-256 point arithmetic

/// A 256-bit unsigned integer stored as four 64-bit limbs (little-endian).
struct BigUInt256 {
    var w: (UInt64, UInt64, UInt64, UInt64) // w.0 = least significant

    static func == (lhs: BigUInt256, rhs: BigUInt256) -> Bool {
        lhs.w.0 == rhs.w.0 && lhs.w.1 == rhs.w.1 && lhs.w.2 == rhs.w.2 && lhs.w.3 == rhs.w.3
    }

    static func != (lhs: BigUInt256, rhs: BigUInt256) -> Bool {
        !(lhs == rhs)
    }

    static let zero = BigUInt256(w: (0, 0, 0, 0))
    static let one  = BigUInt256(w: (1, 0, 0, 0))

    init(w: (UInt64, UInt64, UInt64, UInt64)) { self.w = w }

    init(data: Data) {
        precondition(data.count <= 32)
        let padded = Data(repeating: 0, count: 32 - data.count) + data
        let w3 = padded.withUnsafeBytes { $0.load(fromByteOffset: 0,  as: UInt64.self).bigEndian }
        let w2 = padded.withUnsafeBytes { $0.load(fromByteOffset: 8,  as: UInt64.self).bigEndian }
        let w1 = padded.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt64.self).bigEndian }
        let w0 = padded.withUnsafeBytes { $0.load(fromByteOffset: 24, as: UInt64.self).bigEndian }
        self.w = (w0, w1, w2, w3)
    }

    var data: Data {
        var result = Data(count: 32)
        result.withUnsafeMutableBytes { buf in
            buf.storeBytes(of: w.3.bigEndian, toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: w.2.bigEndian, toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: w.1.bigEndian, toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: w.0.bigEndian, toByteOffset: 24, as: UInt64.self)
        }
        return result
    }

    subscript(index: Int) -> UInt64 {
        get {
            switch index {
            case 0: return w.0
            case 1: return w.1
            case 2: return w.2
            case 3: return w.3
            default: fatalError("index out of range")
            }
        }
        set {
            switch index {
            case 0: w.0 = newValue
            case 1: w.1 = newValue
            case 2: w.2 = newValue
            case 3: w.3 = newValue
            default: fatalError("index out of range")
            }
        }
    }

    var isZero: Bool { w.0 == 0 && w.1 == 0 && w.2 == 0 && w.3 == 0 }

    /// Test bit at position (0 = LSB)
    func bit(_ pos: Int) -> Bool {
        let limb = pos / 64
        let bit = pos % 64
        return (self[limb] >> bit) & 1 == 1
    }

    /// Number of significant bits
    var bitWidth: Int {
        for i in stride(from: 3, through: 0, by: -1) {
            if self[i] != 0 {
                return i * 64 + (64 - self[i].leadingZeroBitCount)
            }
        }
        return 0
    }
}

// Comparison
extension BigUInt256: Comparable {
    static func < (lhs: BigUInt256, rhs: BigUInt256) -> Bool {
        if lhs.w.3 != rhs.w.3 { return lhs.w.3 < rhs.w.3 }
        if lhs.w.2 != rhs.w.2 { return lhs.w.2 < rhs.w.2 }
        if lhs.w.1 != rhs.w.1 { return lhs.w.1 < rhs.w.1 }
        return lhs.w.0 < rhs.w.0
    }
}

// Addition with carry
func bigAdd(_ a: BigUInt256, _ b: BigUInt256) -> (BigUInt256, Bool) {
    var r = BigUInt256.zero
    var carry: Bool = false
    for i in 0..<4 {
        let (s1, c1) = a[i].addingReportingOverflow(b[i])
        let (s2, c2) = s1.addingReportingOverflow(carry ? 1 : 0)
        r[i] = s2
        carry = c1 || c2
    }
    return (r, carry)
}

// Subtraction with borrow
func bigSub(_ a: BigUInt256, _ b: BigUInt256) -> (BigUInt256, Bool) {
    var r = BigUInt256.zero
    var borrow: Bool = false
    for i in 0..<4 {
        let (s1, c1) = a[i].subtractingReportingOverflow(b[i])
        let (s2, c2) = s1.subtractingReportingOverflow(borrow ? 1 : 0)
        r[i] = s2
        borrow = c1 || c2
    }
    return (r, borrow)
}

// MARK: - Modular arithmetic for P-256

struct ModP256 {
    // P-256 prime: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    static let p = BigUInt256(w: (
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001
    ))

    // P-256 order: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    static let n = BigUInt256(w: (
        0xF3B9CAC2FC632551,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000
    ))

    // b coefficient: 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    static let b = BigUInt256(w: (
        0x3BCE3C3E27D2604B,
        0x651D06B0CC53B0F6,
        0xB3EBBD55769886BC,
        0x5AC635D8AA3A93E7
    ))

    static func add(_ a: BigUInt256, _ b: BigUInt256) -> BigUInt256 {
        let (sum, carry) = bigAdd(a, b)
        if carry || sum >= p {
            return bigSub(sum, p).0
        }
        return sum
    }

    static func sub(_ a: BigUInt256, _ b: BigUInt256) -> BigUInt256 {
        let (diff, borrow) = bigSub(a, b)
        if borrow {
            return bigAdd(diff, p).0
        }
        return diff
    }

    /// Modular multiplication using schoolbook with reduction via 2^256 mod p identity
    static func mul(_ a: BigUInt256, _ b: BigUInt256) -> BigUInt256 {
        // Full 512-bit product stored in 8 limbs
        var product = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                let (s1, c1) = product[i + j].addingReportingOverflow(lo)
                let (s2, c2) = s1.addingReportingOverflow(carry)
                product[i + j] = s2
                carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            product[i + 4] = carry
        }
        return reduceModP(product)
    }

    /// Reduce a 512-bit number (8 limbs) modulo p using the identity:
    /// 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)
    /// We iteratively fold the top limbs down until the result fits in 256 bits.
    private static func reduceModP(_ t: [UInt64]) -> BigUInt256 {
        // Work in 32-bit limbs for NIST reduction
        // c = (c15, c14, ..., c1, c0) where each ci is 32 bits
        var c = [Int64](repeating: 0, count: 16)
        for i in 0..<8 {
            c[2*i]     = Int64(t[i] & 0xFFFFFFFF)
            c[2*i + 1] = Int64(t[i] >> 32)
        }

        // Apply NIST P-256 reduction formulas from FIPS 186-4, Section D.2.3
        // Result = T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4 mod p
        // where:
        // T  = (c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0)
        // S1 = (c15, c14, c13, c12, c11, 0,   0,   0  )
        // S2 = (0,   c15, c14, c13, c12, 0,   0,   0  )
        // S3 = (c15, c14, 0,   0,   0,   c10, c9,  c8 )
        // S4 = (c8,  c13, c15, c14, c13, c11, c10, c9 )
        // D1 = (c10, c8,  0,   0,   0,   c13, c12, c11)
        // D2 = (c11, c9,  0,   0,   c15, c14, c13, c12)
        // D3 = (c12, 0,   c10, c9,  c8,  c15, c14, c13)
        // D4 = (c13, 0,   c11, c10, c9,  0,   c15, c14)

        // Use wider accumulators (Int64) to handle carries/borrows
        var r = [Int64](repeating: 0, count: 9) // 8 limbs + overflow

        // T
        for i in 0..<8 { r[i] = c[i] }

        // + 2*S1
        r[3] += 2 * c[11]; r[4] += 2 * c[12]; r[5] += 2 * c[13]; r[6] += 2 * c[14]; r[7] += 2 * c[15]

        // + 2*S2
        r[3] += 2 * c[12]; r[4] += 2 * c[13]; r[5] += 2 * c[14]; r[6] += 2 * c[15]

        // + S3
        r[0] += c[8]; r[1] += c[9]; r[2] += c[10]; r[6] += c[14]; r[7] += c[15]

        // + S4
        r[0] += c[9]; r[1] += c[10]; r[2] += c[11]; r[3] += c[13]; r[4] += c[14]; r[5] += c[15]; r[6] += c[13]; r[7] += c[8]

        // - D1
        r[0] -= c[11]; r[1] -= c[12]; r[2] -= c[13]; r[6] -= c[8]; r[7] -= c[10]

        // - D2
        r[0] -= c[12]; r[1] -= c[13]; r[2] -= c[14]; r[3] -= c[15]; r[6] -= c[9]; r[7] -= c[11]

        // - D3
        r[0] -= c[13]; r[1] -= c[14]; r[2] -= c[15]; r[3] -= c[8]; r[4] -= c[9]; r[5] -= c[10]; r[7] -= c[12]

        // - D4
        r[0] -= c[14]; r[1] -= c[15]; r[3] -= c[9]; r[4] -= c[10]; r[5] -= c[11]; r[7] -= c[13]

        // Propagate carries/borrows through the 32-bit limbs
        // Use floor division to handle negative values correctly
        for i in 0..<8 {
            var carry: Int64
            if r[i] >= 0 {
                carry = r[i] >> 32
            } else {
                // For negative: floor divide by 2^32
                carry = -(((-r[i] - 1) >> 32) + 1)
            }
            r[i+1] += carry
            r[i] -= carry << 32
            // Now r[i] is in [0, 2^32)
        }

        // Convert to BigUInt256, handling potential negative overflow in r[8]
        var result = BigUInt256.zero
        for i in 0..<4 {
            result[i] = UInt64(r[2*i]) | (UInt64(r[2*i+1]) << 32)
        }

        // Handle r[8]: result += r[8] * 2^256 mod p
        // 2^256 mod p = 2^256 - p = 0x00000000FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
        // As BigUInt256: (0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE)
        let residue = BigUInt256(w: (
            0x0000000000000001,
            0xFFFFFFFF00000000,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFE
        ))

        var overflow = r[8]
        while overflow > 0 {
            let (s, carry) = bigAdd(result, residue)
            result = s
            if carry || result >= p {
                result = bigSub(result, p).0
            }
            overflow -= 1
        }
        while overflow < 0 {
            // Subtract residue (or equivalently add p - residue)
            let (d, borrow) = bigSub(result, residue)
            result = d
            if borrow {
                result = bigAdd(result, p).0
            }
            overflow += 1
        }

        // Final reduction
        while result >= p {
            result = bigSub(result, p).0
        }

        return result
    }

    /// Modular squaring
    static func sqr(_ a: BigUInt256) -> BigUInt256 {
        return mul(a, a)
    }

    /// Modular exponentiation (for inversion via Fermat)
    static func pow(_ base: BigUInt256, _ exp: BigUInt256) -> BigUInt256 {
        var result = BigUInt256.one
        var b = base
        let bits = exp.bitWidth
        for i in 0..<bits {
            if exp.bit(i) {
                result = mul(result, b)
            }
            b = sqr(b)
        }
        return result
    }

    /// Modular inverse: a^(p-2) mod p
    static func inv(_ a: BigUInt256) -> BigUInt256 {
        let pMinus2 = bigSub(p, BigUInt256(w: (2, 0, 0, 0))).0
        return pow(a, pMinus2)
    }

    /// Reduce mod n (curve order) - for scalar operations
    static func modN(_ a: BigUInt256) -> BigUInt256 {
        var v = a
        while v >= n {
            v = bigSub(v, n).0
        }
        return v
    }

    /// Reduce a 48-byte value mod n
    static func reduceModN(data: Data) -> BigUInt256 {
        precondition(data.count == 48)
        // Split into high 16 bytes and low 32 bytes
        let high = Data(data[0..<16])
        let low = Data(data[16..<48])

        // result = high * 2^256 + low (mod n)
        // 2^256 mod n = 0x00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF
        let shift = BigUInt256(w: (
            0x0C46353D039CDAAF,
            0x4319055258E8617B,
            0x0000000000000000,
            0x00000000FFFFFFFF
        ))

        var result = BigUInt256(data: low)
        if result >= n {
            result = bigSub(result, n).0
        }

        let h = BigUInt256(data: Data(repeating: 0, count: 16) + high)
        let hTimesShift = mulModN(h, shift)
        result = addModN(result, hTimesShift)

        return result
    }

    static func addModN(_ a: BigUInt256, _ b: BigUInt256) -> BigUInt256 {
        let (sum, carry) = bigAdd(a, b)
        if carry || sum >= n {
            return bigSub(sum, n).0
        }
        return sum
    }

    static func mulModN(_ a: BigUInt256, _ b: BigUInt256) -> BigUInt256 {
        // Full 512-bit product
        var product = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                let (s1, c1) = product[i + j].addingReportingOverflow(lo)
                let (s2, c2) = s1.addingReportingOverflow(carry)
                product[i + j] = s2
                carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            product[i + 4] = carry
        }
        // Reduce mod n using simple shift-and-subtract
        return reduceProductModN(product)
    }

    private static func reduceProductModN(_ product: [UInt64]) -> BigUInt256 {
        // Convert 512-bit product to result mod n
        // Process from high limb down
        // We'll accumulate into a running remainder

        // Start with the top 256 bits
        let hi = BigUInt256(w: (product[4], product[5], product[6], product[7]))
        let lo = BigUInt256(w: (product[0], product[1], product[2], product[3]))

        // hi * 2^256 mod n = hi * (2^256 mod n)
        // 2^256 mod n = 0x00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF
        let r256 = BigUInt256(w: (
            0x0C46353D039CDAAF,
            0x4319055258E8617B,
            0x0000000000000000,
            0x00000000FFFFFFFF
        ))

        // hi * r256 can overflow 256 bits, so we need another round
        // hi < 2^256, r256 < 2^225, product < 2^481
        // We need another level. Let's do it iteratively.
        var hiProduct = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (h, l) = hi[i].multipliedFullWidth(by: r256[j])
                let (s1, c1) = hiProduct[i + j].addingReportingOverflow(l)
                let (s2, c2) = s1.addingReportingOverflow(carry)
                hiProduct[i + j] = s2
                carry = h &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            hiProduct[i + 4] = carry
        }

        // Now reduce hiProduct the same way (recursively, but it converges)
        let hi2 = BigUInt256(w: (hiProduct[4], hiProduct[5], hiProduct[6], hiProduct[7]))
        let lo2 = BigUInt256(w: (hiProduct[0], hiProduct[1], hiProduct[2], hiProduct[3]))

        // hi2 * r256 - one more round should suffice since hi2 should be small
        var hi2Product = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (h, l) = hi2[i].multipliedFullWidth(by: r256[j])
                let (s1, c1) = hi2Product[i + j].addingReportingOverflow(l)
                let (s2, c2) = s1.addingReportingOverflow(carry)
                hi2Product[i + j] = s2
                carry = h &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            hi2Product[i + 4] = carry
        }

        // At this point hi3 should be zero or very small
        let lo3 = BigUInt256(w: (hi2Product[0], hi2Product[1], hi2Product[2], hi2Product[3]))
        // Ignore hi2Product[4..7] - should be zero for reasonable inputs

        // Sum: lo + lo2 + lo3 mod n
        var result = addModN(lo, lo2)
        result = addModN(result, lo3)

        // Handle any remaining high bits from hi2Product
        let hi3 = BigUInt256(w: (hi2Product[4], hi2Product[5], hi2Product[6], hi2Product[7]))
        if !hi3.isZero {
            let extra = mulModN(hi3, r256)
            result = addModN(result, extra)
        }

        while result >= n {
            result = bigSub(result, n).0
        }
        return result
    }
}

// MARK: - P-256 Point

struct P256Point {
    var x: BigUInt256
    var y: BigUInt256
    var z: BigUInt256 // Jacobian coordinate (affine when z=1, infinity when z=0)

    static let infinity = P256Point(x: .zero, y: .one, z: .zero)

    var isInfinity: Bool { z.isZero }

    /// Convert from uncompressed SEC1 encoding (0x04 || x || y)
    init(uncompressed data: Data) throws {
        guard data.count == 65, data[data.startIndex] == 0x04 else {
            throw LatchRelayError.invalidPoint
        }
        self.x = BigUInt256(data: Data(data[data.startIndex+1..<data.startIndex+33]))
        self.y = BigUInt256(data: Data(data[data.startIndex+33..<data.startIndex+65]))
        self.z = .one

        // Verify point is on the P-256 curve: y^2 == x^3 - 3x + b (mod p)
        let x2 = ModP256.sqr(self.x)
        let x3 = ModP256.mul(x2, self.x)
        let threeX = ModP256.mul(BigUInt256(w: (3, 0, 0, 0)), self.x)
        let rhs = ModP256.add(ModP256.sub(x3, threeX), ModP256.b)
        let lhs = ModP256.sqr(self.y)
        guard lhs == rhs else {
            throw LatchRelayError.invalidPoint
        }
    }

    /// Convert from compressed SEC1 encoding (0x02/0x03 || x)
    init(compressed data: Data) throws {
        guard data.count == 33 else {
            throw LatchRelayError.invalidPoint
        }
        let prefix = data[data.startIndex]
        guard prefix == 0x02 || prefix == 0x03 else {
            throw LatchRelayError.invalidPoint
        }
        let xData = Data(data[data.startIndex+1..<data.startIndex+33])
        self.x = BigUInt256(data: xData)
        self.z = .one

        // y^2 = x^3 + ax + b (a = p - 3)
        let x2 = ModP256.sqr(self.x)
        let x3 = ModP256.mul(x2, self.x)
        let ax = ModP256.mul(
            ModP256.sub(ModP256.p, BigUInt256(w: (3, 0, 0, 0))),
            self.x
        )
        let rhs = ModP256.add(ModP256.add(x3, ax), ModP256.b)

        // y = rhs^((p+1)/4) since p ≡ 3 (mod 4)
        let exp = bigAdd(ModP256.p, .one).0
        // (p+1)/4: shift right by 2
        var e = BigUInt256.zero
        e[3] = exp.w.3 >> 2
        e[2] = (exp.w.2 >> 2) | (exp.w.3 << 62)
        e[1] = (exp.w.1 >> 2) | (exp.w.2 << 62)
        e[0] = (exp.w.0 >> 2) | (exp.w.1 << 62)

        self.y = ModP256.pow(rhs, e)

        // Check parity
        let needOdd = prefix == 0x03
        let isOdd = self.y[0] & 1 == 1
        if needOdd != isOdd {
            self.y = ModP256.sub(ModP256.p, self.y)
        }
    }

    init(x: BigUInt256, y: BigUInt256, z: BigUInt256) {
        self.x = x; self.y = y; self.z = z
    }

    /// Convert to affine coordinates
    func affine() -> (BigUInt256, BigUInt256) {
        if isInfinity { return (.zero, .zero) }
        let zInv = ModP256.inv(z)
        let zInv2 = ModP256.sqr(zInv)
        let zInv3 = ModP256.mul(zInv2, zInv)
        return (ModP256.mul(x, zInv2), ModP256.mul(y, zInv3))
    }

    /// Uncompressed SEC1 encoding
    func toUncompressed() -> Data {
        let (ax, ay) = affine()
        var result = Data([0x04])
        result.append(ax.data)
        result.append(ay.data)
        return result
    }

    /// Point doubling in Jacobian coordinates
    static func double(_ p: P256Point) -> P256Point {
        if p.isInfinity { return .infinity }

        let a = ModP256.sqr(p.x)
        let b = ModP256.sqr(p.y)
        let c = ModP256.sqr(b)

        let d: BigUInt256 = {
            let xPlusB = ModP256.add(p.x, b)
            let sq = ModP256.sqr(xPlusB)
            let sub1 = ModP256.sub(sq, a)
            let sub2 = ModP256.sub(sub1, c)
            return ModP256.add(sub2, sub2)
        }()

        let e = ModP256.add(ModP256.add(a, a), a) // 3*a
        // For a = p-3: add 3*a_coeff*z^4
        let z2 = ModP256.sqr(p.z)
        let z4 = ModP256.sqr(z2)
        let aCoeff = ModP256.sub(ModP256.p, BigUInt256(w: (3, 0, 0, 0))) // p-3
        let aZ4 = ModP256.mul(aCoeff, z4)
        let f = ModP256.add(e, aZ4) // 3x^2 + a*z^4

        let x3 = ModP256.sub(ModP256.sqr(f), ModP256.add(d, d))
        let c8 = ModP256.add(ModP256.add(ModP256.add(c, c), ModP256.add(c, c)), ModP256.add(ModP256.add(c, c), ModP256.add(c, c)))
        let y3 = ModP256.sub(ModP256.mul(f, ModP256.sub(d, x3)), c8)
        let z3 = ModP256.mul(ModP256.add(p.y, p.y), p.z)

        return P256Point(x: x3, y: y3, z: z3)
    }

    /// Point addition in Jacobian coordinates
    static func add(_ p1: P256Point, _ p2: P256Point) -> P256Point {
        if p1.isInfinity { return p2 }
        if p2.isInfinity { return p1 }

        let z1sq = ModP256.sqr(p1.z)
        let z2sq = ModP256.sqr(p2.z)
        let u1 = ModP256.mul(p1.x, z2sq)
        let u2 = ModP256.mul(p2.x, z1sq)
        let s1 = ModP256.mul(p1.y, ModP256.mul(p2.z, z2sq))
        let s2 = ModP256.mul(p2.y, ModP256.mul(p1.z, z1sq))

        if u1 == u2 {
            if s1 == s2 {
                return self.double(p1)
            }
            return .infinity
        }

        let h = ModP256.sub(u2, u1)
        let r = ModP256.sub(s2, s1)
        let h2 = ModP256.sqr(h)
        let h3 = ModP256.mul(h, h2)
        let u1h2 = ModP256.mul(u1, h2)

        let x3 = ModP256.sub(
            ModP256.sub(ModP256.sqr(r), h3),
            ModP256.add(u1h2, u1h2)
        )
        let y3 = ModP256.sub(
            ModP256.mul(r, ModP256.sub(u1h2, x3)),
            ModP256.mul(s1, h3)
        )
        let z3 = ModP256.mul(ModP256.mul(p1.z, p2.z), h)

        return P256Point(x: x3, y: y3, z: z3)
    }

    /// Scalar multiplication using double-and-add
    static func mul(_ scalar: BigUInt256, _ point: P256Point) -> P256Point {
        if scalar.isZero { return .infinity }
        var result = P256Point.infinity
        var temp = point
        let bits = scalar.bitWidth
        for i in 0..<bits {
            if scalar.bit(i) {
                result = add(result, temp)
            }
            temp = self.double(temp)
        }
        return result
    }

    /// Negate a point
    static func negate(_ p: P256Point) -> P256Point {
        if p.isInfinity { return .infinity }
        return P256Point(x: p.x, y: ModP256.sub(ModP256.p, p.y), z: p.z)
    }
}

// MARK: - SPAKE2 Constants

enum SPAKE2Constants {
    // M point (compressed): 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
    static let M: P256Point = {
        let data = Data(hexString: "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")!
        return try! P256Point(compressed: data)
    }()

    // N point (compressed): 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
    static let N: P256Point = {
        let data = Data(hexString: "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")!
        return try! P256Point(compressed: data)
    }()
}

// MARK: - SPAKE2 Protocol

public enum LatchRelayError: Error {
    case invalidPoint
    case invalidPubShare
    case pairingFailed(String)
    case channelError(String)
    case connectionClosed
    case timeout
    case verifyRejected
}

/// SPAKE2 key agreement result
struct SPAKE2Result {
    let pairingId: String
    let channelId: String
    let encKey: SymmetricKey
    let role: String
    let pubShare: Data // our public share (uncompressed SEC1)
}

/// Derive pairingId and w from a pairing code
func derivePairingParams(code: String) throws -> (pairingId: String, w: BigUInt256) {
    let window = Int(Date().timeIntervalSince1970) / 600
    let salt = "latch-relay-room-v1\(window)".data(using: .utf8)!
    let seed = pbkdf2SHA256(password: code.uppercased(), salt: salt, iterations: 100_000, keyLength: 32)

    let pairingIdBytes = hkdfExpandSHA256(prk: seed, info: "roomId".data(using: .utf8)!, length: 32)
    let pairingId = pairingIdBytes.map { String(format: "%02x", $0) }.joined()

    let wBytes = hkdfExpandSHA256(prk: seed, info: "spake2-w".data(using: .utf8)!, length: 48)
    let w = ModP256.reduceModN(data: wBytes)
    if w.isZero { throw LatchRelayError.pairingFailed("derived w is zero") }

    return (pairingId, w)
}

/// Derive pairing parameters for both the current and previous time windows
func derivePairingParamsBothWindows(code: String) throws -> (current: (pairingId: String, w: BigUInt256), previous: (pairingId: String, w: BigUInt256)) {
    let window = Int(Date().timeIntervalSince1970) / 600
    let salt1 = "latch-relay-room-v1\(window)".data(using: .utf8)!
    let seed1 = pbkdf2SHA256(password: code.uppercased(), salt: salt1, iterations: 100_000, keyLength: 32)
    let pid1 = hkdfExpandSHA256(prk: seed1, info: "roomId".data(using: .utf8)!, length: 32).map { String(format: "%02x", $0) }.joined()
    let w1Bytes = hkdfExpandSHA256(prk: seed1, info: "spake2-w".data(using: .utf8)!, length: 48)
    let w1 = ModP256.reduceModN(data: w1Bytes)
    if w1.isZero { throw LatchRelayError.pairingFailed("derived w is zero") }

    let salt2 = "latch-relay-room-v1\(window - 1)".data(using: .utf8)!
    let seed2 = pbkdf2SHA256(password: code.uppercased(), salt: salt2, iterations: 100_000, keyLength: 32)
    let pid2 = hkdfExpandSHA256(prk: seed2, info: "roomId".data(using: .utf8)!, length: 32).map { String(format: "%02x", $0) }.joined()
    let w2Bytes = hkdfExpandSHA256(prk: seed2, info: "spake2-w".data(using: .utf8)!, length: 48)
    let w2 = ModP256.reduceModN(data: w2Bytes)
    if w2.isZero { throw LatchRelayError.pairingFailed("derived w is zero") }

    return (current: (pid1, w1), previous: (pid2, w2))
}

/// SPAKE2 start: generates scalar, computes pubShare = scalar*G + w*M
/// Both peers blind with M (pubShare is sent before role assignment).
func spake2Start(w: BigUInt256) -> (scalar: BigUInt256, pubShare: Data) {
    var scalarBytes = Data(count: 32)
    scalarBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
    var scalar = BigUInt256(data: scalarBytes)
    scalar = ModP256.modN(scalar)
    if scalar.isZero { scalar = .one }

    let sG = p256BasePointMul(scalar)
    let wM = P256Point.mul(w, SPAKE2Constants.M)
    let pub = P256Point.add(sG, wM)

    return (scalar, pub.toUncompressed())
}

/// SPAKE2 initiator finish: K = scalar * (peerPub - w*M)
func spake2InitiatorFinish(x: BigUInt256, w: BigUInt256, peerPubShare: Data, myPubShare: Data, pairingId: String, myId: String = "", peerId: String = "") throws -> (channelId: String, encKey: SymmetricKey) {
    let peerPub = try P256Point(uncompressed: peerPubShare)
    let wM = P256Point.mul(w, SPAKE2Constants.M)
    let base = P256Point.add(peerPub, P256Point.negate(wM))
    let K = P256Point.mul(x, base)

    // Initiator is prover, peer (responder) is verifier
    return try deriveKeys(K: K, pA: myPubShare, pB: peerPubShare, pairingId: pairingId, idProver: myId, idVerifier: peerId)
}

/// SPAKE2 responder finish: K = scalar * (peerPub - w*M)
func spake2ResponderFinish(y: BigUInt256, w: BigUInt256, peerPubShare: Data, myPubShare: Data, pairingId: String, myId: String = "", peerId: String = "") throws -> (channelId: String, encKey: SymmetricKey) {
    let peerPub = try P256Point(uncompressed: peerPubShare)
    let wM = P256Point.mul(w, SPAKE2Constants.M)
    let base = P256Point.add(peerPub, P256Point.negate(wM))
    let K = P256Point.mul(y, base)

    // Peer (initiator) is prover, responder is verifier
    return try deriveKeys(K: K, pA: peerPubShare, pB: myPubShare, pairingId: pairingId, idProver: peerId, idVerifier: myId)
}

/// Derive channelId and encKey from shared secret K
private func deriveKeys(K: P256Point, pA: Data, pB: Data, pairingId: String, idProver: String = "", idVerifier: String = "") throws -> (channelId: String, encKey: SymmetricKey) {
    // K as uncompressed SEC1 point (0x04 || x || y, 65 bytes)
    let kUncompressed = K.toUncompressed()

    // Build transcript TT per RFC 9382
    var tt = Data()
    let context = ("latch-relay-v1" + pairingId).data(using: .utf8)!
    appendLengthPrefixed(&tt, context)
    appendLengthPrefixed(&tt, idProver.data(using: .utf8)!)
    appendLengthPrefixed(&tt, idVerifier.data(using: .utf8)!)
    appendLengthPrefixed(&tt, SPAKE2Constants.M.toUncompressed())
    appendLengthPrefixed(&tt, SPAKE2Constants.N.toUncompressed())
    appendLengthPrefixed(&tt, pA)
    appendLengthPrefixed(&tt, pB)
    appendLengthPrefixed(&tt, kUncompressed)

    let ttHash = SHA256.hash(data: tt)
    let ttHashData = Data(ttHash)

    // ISK = HKDF-Extract(salt, ttHash)
    let salt = ("latch-relay-isk" + pairingId).data(using: .utf8)!
    let ISK = HMAC<SHA256>.authenticationCode(for: ttHashData, using: SymmetricKey(data: salt))

    // channelId = HKDF-Expand(ISK, "channel", 32)
    let channelIdBytes = hkdfExpandSHA256(prk: Data(ISK), info: "channel".data(using: .utf8)!, length: 32)
    let channelId = channelIdBytes.map { String(format: "%02x", $0) }.joined()

    // encKey = HKDF-Expand(ISK, "encrypt", 32)
    let encKeyBytes = hkdfExpandSHA256(prk: Data(ISK), info: "encrypt".data(using: .utf8)!, length: 32)
    let encKey = SymmetricKey(data: encKeyBytes)

    return (channelId, encKey)
}

/// Append length-prefixed data to transcript (8-byte LE length prefix)
private func appendLengthPrefixed(_ tt: inout Data, _ data: Data) {
    var len = UInt64(data.count).littleEndian
    tt.append(Data(bytes: &len, count: 8))
    tt.append(data)
}

// MARK: - P-256 Base Point Multiplication

/// Generator point for P-256
private let p256G: P256Point = {
    let gx = BigUInt256(data: Data(hexString: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!)
    let gy = BigUInt256(data: Data(hexString: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")!)
    return P256Point(x: gx, y: gy, z: .one)
}()

func p256BasePointMul(_ scalar: BigUInt256) -> P256Point {
    return P256Point.mul(scalar, p256G)
}

// MARK: - PBKDF2

func pbkdf2SHA256(password: String, salt: Data, iterations: Int, keyLength: Int) -> Data {
    let passwordData = password.data(using: .utf8)!
    var derivedKey = Data(count: keyLength)
    let _ = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
        passwordData.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    keyLength
                )
            }
        }
    }
    return derivedKey
}

// MARK: - HKDF-Expand (SHA-256)

func hkdfExpandSHA256(prk: Data, info: Data, length: Int) -> Data {
    let hashLen = 32
    let n = (length + hashLen - 1) / hashLen
    var okm = Data()
    var t = Data()
    let key = SymmetricKey(data: prk)
    for i in 1...n {
        var input = t
        input.append(info)
        input.append(UInt8(i))
        let mac = HMAC<SHA256>.authenticationCode(for: input, using: key)
        t = Data(mac)
        okm.append(t)
    }
    return Data(okm.prefix(length))
}

// MARK: - Challenge-Response MAC

/// Compute challenge-response MAC
public func computeChallengeMAC(encKey: SymmetricKey, channelId: String, nonce: Data, id: String, role: String) -> Data {
    var message = Data()
    message.append("challenge\0".data(using: .utf8)!)
    message.append(channelId.data(using: .utf8)!)
    message.append(Data([0]))
    message.append(nonce)
    message.append(Data([0]))
    message.append(id.data(using: .utf8)!)
    message.append(Data([0]))
    message.append(role.data(using: .utf8)!)
    let mac = HMAC<SHA256>.authenticationCode(for: message, using: encKey)
    return Data(mac)
}

/// Verify a peer's challenge-response MAC
public func verifyChallengeMAC(encKey: SymmetricKey, channelId: String, nonce: Data, id: String, role: String, mac: Data) -> Bool {
    let expected = computeChallengeMAC(encKey: encKey, channelId: channelId, nonce: nonce, id: id, role: role)
    // Constant-time comparison
    guard expected.count == mac.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<expected.count {
        diff |= expected[i] ^ mac[i]
    }
    return diff == 0
}

// MARK: - AES-256-GCM

/// Encrypt data with AES-256-GCM. Returns nonce(12) || ciphertext || tag(16).
public func aesGCMEncrypt(plaintext: Data, key: SymmetricKey, aad: Data) throws -> Data {
    let nonce = AES.GCM.Nonce()
    let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
    var wire = Data()
    wire.append(contentsOf: nonce)
    wire.append(sealed.ciphertext)
    wire.append(sealed.tag)
    return wire
}

/// Decrypt AES-256-GCM. Input: nonce(12) || ciphertext || tag(16).
public func aesGCMDecrypt(ciphertext: Data, key: SymmetricKey, aad: Data) throws -> Data {
    guard ciphertext.count >= 28 else { throw LatchRelayError.channelError("ciphertext too short") }
    let nonceData = ciphertext.prefix(12)
    let nonce = try AES.GCM.Nonce(data: nonceData)
    let tagStart = ciphertext.count - 16
    let ct = ciphertext[12..<tagStart]
    let tag = ciphertext[tagStart...]
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
    return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
}

// MARK: - Base64url

/// Encode data to unpadded base64url
public func base64urlEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Decode unpadded base64url to data
public func base64urlDecode(_ string: String) -> Data? {
    var s = string
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let pad = (4 - s.count % 4) % 4
    s += String(repeating: "=", count: pad)
    return Data(base64Encoded: s)
}

// MARK: - Data hex extension

extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            bytes.append(byte)
        }
        self.init(bytes)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
