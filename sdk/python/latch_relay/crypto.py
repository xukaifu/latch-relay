"""Cryptographic primitives for the latch-relay protocol.

Implements SPAKE2 (P-256), PBKDF2, HKDF, HMAC-SHA256, and AES-256-GCM.

SPAKE2 adaptation: Both peers blind with M (pubShare is sent before role
assignment). Role (assigned by server in pair_matched) only affects
transcript ordering (who is prover vs verifier).
"""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# P-256 curve order and prime
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

# RFC 9382 Section 4 M and N points (compressed SEC1)
_M_COMPRESSED = bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
_N_COMPRESSED = bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")


def _decompress_point(compressed: bytes) -> tuple[int, int]:
    """Decompress a SEC1 compressed point on P-256."""
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], "big")
    p = P256_PRIME
    y_sq = (pow(x, 3, p) - 3 * x + P256_B) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if (y % 2) != (prefix - 2):
        y = p - y
    return (x, y)


M_POINT = _decompress_point(_M_COMPRESSED)
N_POINT = _decompress_point(_N_COMPRESSED)


def _point_to_uncompressed(x: int, y: int) -> bytes:
    """Encode a P-256 point as uncompressed SEC1 (0x04 || x || y)."""
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _uncompressed_to_point(data: bytes) -> tuple[int, int]:
    """Decode uncompressed SEC1 point."""
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Invalid uncompressed SEC1 point")
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    p = P256_PRIME
    if pow(y, 2, p) != (pow(x, 3, p) - 3 * x + P256_B) % p:
        raise ValueError("Point not on P-256 curve")
    return (x, y)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    """Add two P-256 points. None represents the point at infinity."""
    p = P256_PRIME
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 == y2:
            if y1 == 0:
                return None
            lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
        else:
            return None
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _point_neg(point: tuple[int, int]) -> tuple[int, int]:
    """Negate a P-256 point."""
    return (point[0], P256_PRIME - point[1])


def _point_mult(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    """Double-and-add scalar multiplication on P-256."""
    if scalar == 0:
        raise ValueError("Scalar must not be zero")
    if scalar < 0:
        scalar = scalar % P256_ORDER
    result = None
    current = point
    s = scalar
    while s > 0:
        if s & 1:
            result = _point_add(result, current) if result else current
        current = _point_add(current, current)
        s >>= 1
    return result


def _generator_mult(scalar: int) -> tuple[int, int]:
    """Multiply the P-256 generator G by a scalar using the cryptography library."""
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    return (nums.x, nums.y)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (no Extract step)."""
    h = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return h.derive(prk)


def _derive_pairing_for_window(code: str, window: int) -> tuple[str, int]:
    """Derive pairing_id and w for a specific time window.

    Returns (pairing_id_hex, w_scalar).
    """
    salt = f"latch-relay-room-v1{window}".encode()
    seed = hashlib.pbkdf2_hmac("sha256", code.upper().encode(), salt, 100000, dklen=32)
    pairing_id = hkdf_expand(seed, b"roomId", 32).hex()
    w_bytes = hkdf_expand(seed, b"spake2-w", 48)
    w = int.from_bytes(w_bytes, "big") % P256_ORDER
    if w == 0:
        raise ValueError("Derived w is zero; invalid pairing parameters")
    return pairing_id, w


def derive_pairing(code: str) -> tuple[str, int]:
    """Derive pairing_id and w from a pairing code.

    Returns (pairing_id_hex, w_scalar).
    """
    window = int(time.time()) // 600
    return _derive_pairing_for_window(code, window)


def derive_pairing_both_windows(code: str) -> tuple[tuple[str, int], tuple[str, int]]:
    """Derive pairing_id and w for both current and previous time windows.

    Returns ((current_pairing_id, current_w), (previous_pairing_id, previous_w)).
    """
    window = int(time.time()) // 600
    current = _derive_pairing_for_window(code, window)
    previous = _derive_pairing_for_window(code, window - 1)
    return current, previous


@dataclass
class SPAKE2State:
    """State from generating a SPAKE2 keypair."""
    scalar: int
    pub_share: bytes  # uncompressed SEC1 (65 bytes)
    role: str  # "initiator" or "responder"
    w: int


def spake2_keypair(w: int, role: str = "initiator") -> SPAKE2State:
    """Generate a SPAKE2 keypair.

    Both peers blind with M (pubShare is sent before role assignment).
    The role parameter is stored for transcript construction.
    """
    scalar = int.from_bytes(os.urandom(32), "big") % P256_ORDER
    if scalar == 0:
        scalar = 1

    xG = _generator_mult(scalar)
    wM = _point_mult(w, M_POINT)
    pub = _point_add(xG, wM)
    pub_share = _point_to_uncompressed(pub[0], pub[1])
    return SPAKE2State(scalar=scalar, pub_share=pub_share, role=role, w=w)


def spake2_finish(
    state: SPAKE2State,
    peer_pub_share: bytes,
    pairing_id: str,
    initiator_id: str,
    responder_id: str,
) -> bytes:
    """Complete the SPAKE2 exchange and return Ke.

    Both peers blinded with M, so K = scalar * (peer_share - w*M).
    """
    peer_point = _uncompressed_to_point(peer_pub_share)

    # Both sides subtract w*M (since both blinded with M)
    wM = _point_mult(state.w, M_POINT)
    base = _point_add(peer_point, _point_neg(wM))
    K = _point_mult(state.scalar, base)

    # Determine pA and pB based on role
    if state.role == "initiator":
        pA = state.pub_share
        pB = peer_pub_share
    else:
        pA = peer_pub_share
        pB = state.pub_share

    # Build transcript TT (RFC 9382)
    context = b"latch-relay-v1" + pairing_id.encode()
    M_uncompressed = _point_to_uncompressed(*M_POINT)
    N_uncompressed = _point_to_uncompressed(*N_POINT)
    K_uncompressed = _point_to_uncompressed(K[0], K[1])

    tt = b""
    for item in [context, initiator_id.encode(), responder_id.encode(),
                 M_uncompressed, N_uncompressed, pA, pB, K_uncompressed]:
        tt += len(item).to_bytes(8, "little") + item

    return hashlib.sha256(tt).digest()


def derive_channel_keys(Ke: bytes, pairing_id: str) -> tuple[str, bytes]:
    """Derive channel_id and encryption key from Ke.

    Returns (channel_id_hex, enc_key).
    """
    salt = b"latch-relay-isk" + pairing_id.encode()
    # HKDF-Extract: ISK = HMAC-SHA256(salt, Ke)
    h = crypto_hmac.HMAC(salt, hashes.SHA256())
    h.update(Ke)
    ISK = h.finalize()

    channel_id = hkdf_expand(ISK, b"channel", 32).hex()
    enc_key = hkdf_expand(ISK, b"encrypt", 32)
    return channel_id, enc_key


def compute_mac(enc_key: bytes, channel_id: str, nonce: bytes, peer_id: str, role: str) -> bytes:
    """Compute HMAC-SHA256 challenge-response MAC."""
    msg = (b"challenge\x00" + channel_id.encode() + b"\x00" +
           nonce + b"\x00" + peer_id.encode() + b"\x00" + role.encode())
    h = crypto_hmac.HMAC(enc_key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def verify_mac(enc_key: bytes, channel_id: str, nonce: bytes, peer_id: str, role: str, mac: bytes) -> bool:
    """Verify an HMAC-SHA256 challenge-response MAC (constant-time)."""
    expected = compute_mac(enc_key, channel_id, nonce, peer_id, role)
    return stdlib_hmac.compare_digest(expected, mac)


def encrypt(enc_key: bytes, plaintext: bytes, channel_id: str) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) || ciphertext+tag."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(enc_key)
    ct = aesgcm.encrypt(nonce, plaintext, channel_id.encode())
    return nonce + ct


def decrypt(enc_key: bytes, data: bytes, channel_id: str) -> bytes:
    """AES-256-GCM decrypt. Input is nonce(12) || ciphertext+tag."""
    if len(data) < 28:
        raise ValueError("ciphertext too short")
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(enc_key)
    return aesgcm.decrypt(nonce, ct, channel_id.encode())
