"""Tests for latch_relay.crypto."""

import os
import time

import pytest

from latch_relay.crypto import (
    SPAKE2State,
    M_POINT,
    N_POINT,
    P256_ORDER,
    _decompress_point,
    _generator_mult,
    _point_add,
    _point_mult,
    _point_neg,
    _point_to_uncompressed,
    _uncompressed_to_point,
    compute_mac,
    decrypt,
    derive_channel_keys,
    derive_pairing,
    encrypt,
    hkdf_expand,
    spake2_finish,
    spake2_keypair,
    verify_mac,
)


class TestPointArithmetic:
    """Test basic P-256 point operations."""

    def test_decompress_m(self):
        """M point decompresses to a valid curve point."""
        x, y = M_POINT
        # Verify on curve: y^2 = x^3 - 3x + b (mod p)
        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        lhs = pow(y, 2, p)
        rhs = (pow(x, 3, p) - 3 * x + b) % p
        assert lhs == rhs

    def test_decompress_n(self):
        """N point decompresses to a valid curve point."""
        x, y = N_POINT
        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        lhs = pow(y, 2, p)
        rhs = (pow(x, 3, p) - 3 * x + b) % p
        assert lhs == rhs

    def test_generator_mult(self):
        """Generator multiplication gives a valid curve point."""
        scalar = int.from_bytes(os.urandom(32), "big") % P256_ORDER
        if scalar == 0:
            scalar = 1
        x, y = _generator_mult(scalar)
        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        assert pow(y, 2, p) == (pow(x, 3, p) - 3 * x + b) % p

    def test_point_add_identity(self):
        """Adding None (identity) returns the other point."""
        assert _point_add(None, M_POINT) == M_POINT
        assert _point_add(M_POINT, None) == M_POINT

    def test_point_neg(self):
        """Point + (-Point) = identity."""
        neg = _point_neg(M_POINT)
        result = _point_add(M_POINT, neg)
        assert result is None

    def test_uncompressed_roundtrip(self):
        """SEC1 uncompressed encoding roundtrips."""
        x, y = M_POINT
        data = _point_to_uncompressed(x, y)
        assert len(data) == 65
        assert data[0] == 0x04
        x2, y2 = _uncompressed_to_point(data)
        assert (x, y) == (x2, y2)


class TestHKDF:
    def test_hkdf_expand_deterministic(self):
        """HKDF-Expand is deterministic."""
        prk = os.urandom(32)
        a = hkdf_expand(prk, b"test-info", 32)
        b_result = hkdf_expand(prk, b"test-info", 32)
        assert a == b_result

    def test_hkdf_expand_different_info(self):
        """Different info produces different output."""
        prk = os.urandom(32)
        a = hkdf_expand(prk, b"info-a", 32)
        b_result = hkdf_expand(prk, b"info-b", 32)
        assert a != b_result


class TestDerivepairing:
    def test_deterministic(self):
        """Same code in same time window gives same result."""
        code = "TESTCODE"
        pid1, w1 = derive_pairing(code)
        pid2, w2 = derive_pairing(code)
        assert pid1 == pid2
        assert w1 == w2

    def test_case_insensitive(self):
        """Codes are uppercased before derivation."""
        pid1, w1 = derive_pairing("testcode")
        pid2, w2 = derive_pairing("TESTCODE")
        assert pid1 == pid2
        assert w1 == w2

    def test_different_codes(self):
        """Different codes produce different pairing IDs."""
        pid1, _ = derive_pairing("CODE-AAA")
        pid2, _ = derive_pairing("CODE-BBB")
        assert pid1 != pid2

    def test_w_in_range(self):
        """w is in [0, P256_ORDER)."""
        _, w = derive_pairing("ANYCODE")
        assert 0 < w < P256_ORDER


class TestSPAKE2:
    def test_key_agreement(self):
        """Two local SPAKE2 instances derive the same Ke."""
        w = int.from_bytes(os.urandom(32), "big") % P256_ORDER
        if w == 0:
            w = 1
        pairing_id = os.urandom(32).hex()

        # Both peers generate keypairs (both blind with M)
        alice = spake2_keypair(w, "initiator")
        bob = spake2_keypair(w, "responder")

        # Both finish the exchange
        alice_id = "alice"
        bob_id = "bob"

        Ke_alice = spake2_finish(alice, bob.pub_share, pairing_id, alice_id, bob_id)
        Ke_bob = spake2_finish(bob, alice.pub_share, pairing_id, alice_id, bob_id)

        assert Ke_alice == Ke_bob
        assert len(Ke_alice) == 32

    def test_different_w_different_keys(self):
        """Different w values produce different Ke."""
        pairing_id = os.urandom(32).hex()
        w1 = 12345
        w2 = 67890

        a1 = spake2_keypair(w1, "initiator")
        b1 = spake2_keypair(w1, "responder")
        Ke1 = spake2_finish(a1, b1.pub_share, pairing_id, "a", "b")

        a2 = spake2_keypair(w2, "initiator")
        b2 = spake2_keypair(w2, "responder")
        Ke2 = spake2_finish(a2, b2.pub_share, pairing_id, "a", "b")

        assert Ke1 != Ke2

    def test_pub_share_format(self):
        """Public shares are 65-byte uncompressed SEC1 points."""
        w = 42
        state = spake2_keypair(w)
        assert len(state.pub_share) == 65
        assert state.pub_share[0] == 0x04


class TestDeriveChannelKeys:
    def test_deterministic(self):
        """Same Ke and pairing_id give same channel keys."""
        Ke = os.urandom(32)
        pid = os.urandom(32).hex()
        ch1, ek1 = derive_channel_keys(Ke, pid)
        ch2, ek2 = derive_channel_keys(Ke, pid)
        assert ch1 == ch2
        assert ek1 == ek2

    def test_channel_id_is_hex(self):
        """Channel ID is a 64-char hex string."""
        Ke = os.urandom(32)
        pid = os.urandom(32).hex()
        ch, _ = derive_channel_keys(Ke, pid)
        assert len(ch) == 64
        int(ch, 16)  # should not raise

    def test_enc_key_length(self):
        """Encryption key is 32 bytes."""
        Ke = os.urandom(32)
        pid = os.urandom(32).hex()
        _, ek = derive_channel_keys(Ke, pid)
        assert len(ek) == 32


class TestMAC:
    def test_compute_verify(self):
        """compute_mac and verify_mac are consistent."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        nonce = os.urandom(32)
        pid = "test-peer"
        role = "initiator"

        mac = compute_mac(key, ch, nonce, pid, role)
        assert verify_mac(key, ch, nonce, pid, role, mac)

    def test_wrong_key_fails(self):
        """Wrong key fails verification."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        nonce = os.urandom(32)
        mac = compute_mac(key, ch, nonce, "peer", "initiator")
        wrong_key = os.urandom(32)
        assert not verify_mac(wrong_key, ch, nonce, "peer", "initiator", mac)

    def test_wrong_role_fails(self):
        """Wrong role fails verification."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        nonce = os.urandom(32)
        mac = compute_mac(key, ch, nonce, "peer", "initiator")
        assert not verify_mac(key, ch, nonce, "peer", "responder", mac)


class TestAESGCM:
    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt returns original plaintext."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        plaintext = b"Hello, world!"

        ct = encrypt(key, plaintext, ch)
        result = decrypt(key, ct, ch)
        assert result == plaintext

    def test_ciphertext_format(self):
        """Ciphertext is nonce(12) + ct + tag(16)."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        plaintext = b"test"

        ct = encrypt(key, plaintext, ch)
        # 12 (nonce) + len(plaintext) + 16 (tag)
        assert len(ct) == 12 + len(plaintext) + 16

    def test_wrong_key_fails(self):
        """Decryption with wrong key raises."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        ct = encrypt(key, b"test", ch)
        wrong_key = os.urandom(32)
        with pytest.raises(Exception):
            decrypt(wrong_key, ct, ch)

    def test_wrong_aad_fails(self):
        """Decryption with wrong AAD raises."""
        key = os.urandom(32)
        ch1 = os.urandom(32).hex()
        ch2 = os.urandom(32).hex()
        ct = encrypt(key, b"test", ch1)
        with pytest.raises(Exception):
            decrypt(key, ct, ch2)

    def test_empty_plaintext(self):
        """Empty plaintext roundtrips correctly."""
        key = os.urandom(32)
        ch = os.urandom(32).hex()
        ct = encrypt(key, b"", ch)
        assert decrypt(key, ct, ch) == b""
