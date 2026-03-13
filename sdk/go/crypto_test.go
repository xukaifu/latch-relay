package latchrelay

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestUnmarshalCompressedM(t *testing.T) {
	// Verify M point is on P-256
	if spakeM == nil {
		t.Fatal("M point not initialized")
	}
	if !p256.IsOnCurve(spakeM.x, spakeM.y) {
		t.Fatal("M is not on P-256")
	}
}

func TestUnmarshalCompressedN(t *testing.T) {
	// Verify N point is on P-256
	if spakeN == nil {
		t.Fatal("N point not initialized")
	}
	if !p256.IsOnCurve(spakeN.x, spakeN.y) {
		t.Fatal("N is not on P-256")
	}
}

func TestDerivePairingKeysForWindow(t *testing.T) {
	// Test determinism: same code + window → same output
	pairingID1, w1 := derivePairingKeysForWindow("TESTCODE", 100)
	pairingID2, w2 := derivePairingKeysForWindow("TESTCODE", 100)

	if pairingID1 != pairingID2 {
		t.Fatalf("pairingID mismatch: %s vs %s", pairingID1, pairingID2)
	}
	if w1.Cmp(w2) != 0 {
		t.Fatalf("w mismatch")
	}

	// Case insensitive
	pairingID3, w3 := derivePairingKeysForWindow("testcode", 100)
	if pairingID3 != pairingID1 {
		t.Fatalf("case insensitive pairingID mismatch")
	}
	if w3.Cmp(w1) != 0 {
		t.Fatalf("case insensitive w mismatch")
	}

	// Different window → different output
	pairingID4, _ := derivePairingKeysForWindow("TESTCODE", 101)
	if pairingID4 == pairingID1 {
		t.Fatalf("different window should produce different pairingID")
	}

	// w must be in [0, n)
	if w1.Sign() < 0 || w1.Cmp(p256N) >= 0 {
		t.Fatalf("w out of range")
	}

	// pairingID must be 64 hex chars (32 bytes)
	if len(pairingID1) != 64 {
		t.Fatalf("pairingID length: got %d, want 64", len(pairingID1))
	}
}

func TestHKDFExpand(t *testing.T) {
	prk := bytes.Repeat([]byte{0x42}, 32)
	out1 := hkdfExpand(prk, []byte("test-info"), 32)
	out2 := hkdfExpand(prk, []byte("test-info"), 32)

	if !bytes.Equal(out1, out2) {
		t.Fatal("hkdfExpand not deterministic")
	}

	// Different info → different output
	out3 := hkdfExpand(prk, []byte("other-info"), 32)
	if bytes.Equal(out1, out3) {
		t.Fatal("different info should produce different output")
	}

	// Test different lengths
	out16 := hkdfExpand(prk, []byte("test-info"), 16)
	if len(out16) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(out16))
	}
	// First 16 bytes should match
	if !bytes.Equal(out1[:16], out16) {
		t.Fatal("shorter output should be prefix of longer")
	}

	out48 := hkdfExpand(prk, []byte("test-info"), 48)
	if len(out48) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(out48))
	}
}

func TestSPAKE2RejectsZeroW(t *testing.T) {
	// w = nil should be rejected
	_, err := NewSPAKE2("initiator", nil)
	if err == nil {
		t.Fatal("expected error for nil w")
	}

	// w = 0 should be rejected
	_, err = NewSPAKE2("initiator", big.NewInt(0))
	if err == nil {
		t.Fatal("expected error for zero w")
	}

	// w = 1 should succeed
	_, err = NewSPAKE2("initiator", big.NewInt(1))
	if err != nil {
		t.Fatalf("expected success for w=1, got: %v", err)
	}
}

func TestSPAKE2KeyAgreement(t *testing.T) {
	w := big.NewInt(12345678)

	alice, err := NewSPAKE2("initiator", w)
	if err != nil {
		t.Fatalf("alice init: %v", err)
	}

	bob, err := NewSPAKE2("initiator", w)
	if err != nil {
		t.Fatalf("bob init: %v", err)
	}
	// Server assigns roles after pubShare exchange
	bob.Role = "responder"

	pairingID := "test-pairing-id"

	keAlice, err := alice.Finish(bob.PubShare(), pairingID, "alice", "bob")
	if err != nil {
		t.Fatalf("alice finish: %v", err)
	}

	keBob, err := bob.Finish(alice.PubShare(), pairingID, "bob", "alice")
	if err != nil {
		t.Fatalf("bob finish: %v", err)
	}

	if !bytes.Equal(keAlice, keBob) {
		t.Fatalf("key mismatch:\n  alice: %s\n  bob:   %s",
			hex.EncodeToString(keAlice), hex.EncodeToString(keBob))
	}

	// Keys should be 32 bytes (SHA-256 output)
	if len(keAlice) != 32 {
		t.Fatalf("expected 32 byte key, got %d", len(keAlice))
	}
}

func TestSPAKE2DifferentW(t *testing.T) {
	w1 := big.NewInt(111111)
	w2 := big.NewInt(222222)

	alice, _ := NewSPAKE2("initiator", w1)
	bob, _ := NewSPAKE2("initiator", w2)
	bob.Role = "responder"

	keAlice, err := alice.Finish(bob.PubShare(), "pid", "a", "b")
	if err != nil {
		t.Fatalf("alice finish: %v", err)
	}

	keBob, err := bob.Finish(alice.PubShare(), "pid", "b", "a")
	if err != nil {
		t.Fatalf("bob finish: %v", err)
	}

	// Different w values should produce different keys
	if bytes.Equal(keAlice, keBob) {
		t.Fatal("different w should produce different keys")
	}
}

func TestSPAKE2PubShareFormat(t *testing.T) {
	w := big.NewInt(42)
	s, err := NewSPAKE2("initiator", w)
	if err != nil {
		t.Fatal(err)
	}

	pub := s.PubShare()
	// Uncompressed SEC1: 0x04 || x(32) || y(32) = 65 bytes
	if len(pub) != 65 {
		t.Fatalf("expected 65 bytes, got %d", len(pub))
	}
	if pub[0] != 0x04 {
		t.Fatalf("expected 0x04 prefix, got 0x%02x", pub[0])
	}

	// Should be a valid point on P-256
	x, y := elliptic.Unmarshal(p256, pub)
	if x == nil {
		t.Fatal("pubShare is not a valid P-256 point")
	}
	if !p256.IsOnCurve(x, y) {
		t.Fatal("pubShare not on curve")
	}
}

func TestDeriveChannelKeys(t *testing.T) {
	ke := bytes.Repeat([]byte{0xAB}, 32)
	pairingID := "test-pairing"

	channelID, encKey := DeriveChannelKeys(ke, pairingID)

	// channelID should be 64 hex chars
	if len(channelID) != 64 {
		t.Fatalf("channelID length: got %d, want 64", len(channelID))
	}

	// encKey should be 32 bytes
	if len(encKey) != 32 {
		t.Fatalf("encKey length: got %d, want 32", len(encKey))
	}

	// Deterministic
	channelID2, encKey2 := DeriveChannelKeys(ke, pairingID)
	if channelID != channelID2 {
		t.Fatal("channelID not deterministic")
	}
	if !bytes.Equal(encKey, encKey2) {
		t.Fatal("encKey not deterministic")
	}

	// Different pairingID → different keys
	channelID3, encKey3 := DeriveChannelKeys(ke, "other-pairing")
	if channelID == channelID3 {
		t.Fatal("different pairingID should produce different channelID")
	}
	if bytes.Equal(encKey, encKey3) {
		t.Fatal("different pairingID should produce different encKey")
	}
}

func TestChallengeMac(t *testing.T) {
	encKey := bytes.Repeat([]byte{0xCD}, 32)
	channelID := "test-channel"
	nonce := bytes.Repeat([]byte{0x01}, 32)
	id := "peer1"
	role := "initiator"

	mac := ComputeChallengeMac(encKey, channelID, nonce, id, role)

	// 32 bytes (HMAC-SHA256)
	if len(mac) != 32 {
		t.Fatalf("MAC length: got %d, want 32", len(mac))
	}

	// Verify should succeed
	if !VerifyChallengeMac(encKey, channelID, nonce, id, role, mac) {
		t.Fatal("MAC verification failed")
	}

	// Wrong key should fail
	wrongKey := bytes.Repeat([]byte{0xEF}, 32)
	if VerifyChallengeMac(wrongKey, channelID, nonce, id, role, mac) {
		t.Fatal("MAC should fail with wrong key")
	}

	// Wrong role should fail
	if VerifyChallengeMac(encKey, channelID, nonce, id, "responder", mac) {
		t.Fatal("MAC should fail with wrong role")
	}

	// Wrong nonce should fail
	wrongNonce := bytes.Repeat([]byte{0x02}, 32)
	if VerifyChallengeMac(encKey, channelID, wrongNonce, id, role, mac) {
		t.Fatal("MAC should fail with wrong nonce")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	channelID := "test-channel"
	plaintext := []byte("hello, world!")

	ciphertext, err := Encrypt(key, plaintext, channelID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Should be nonce(12) + ciphertext(len(plaintext) + 16 tag)
	expectedLen := 12 + len(plaintext) + 16
	if len(ciphertext) != expectedLen {
		t.Fatalf("ciphertext length: got %d, want %d", len(ciphertext), expectedLen)
	}

	decrypted, err := Decrypt(key, ciphertext, channelID)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCMWrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	wrongKey := bytes.Repeat([]byte{0x43}, 32)
	channelID := "ch"

	ct, _ := Encrypt(key, []byte("secret"), channelID)
	_, err := Decrypt(wrongKey, ct, channelID)
	if err == nil {
		t.Fatal("should fail with wrong key")
	}
}

func TestAESGCMWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)

	ct, _ := Encrypt(key, []byte("secret"), "channel1")
	_, err := Decrypt(key, ct, "channel2")
	if err == nil {
		t.Fatal("should fail with wrong AAD")
	}
}

func TestAESGCMDifferentNonces(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	channelID := "ch"
	plaintext := []byte("same message")

	ct1, _ := Encrypt(key, plaintext, channelID)
	ct2, _ := Encrypt(key, plaintext, channelID)

	// Should produce different ciphertexts due to random nonce
	if bytes.Equal(ct1, ct2) {
		t.Fatal("encryptions with random nonce should differ")
	}

	// Both should decrypt correctly
	pt1, _ := Decrypt(key, ct1, channelID)
	pt2, _ := Decrypt(key, ct2, channelID)
	if !bytes.Equal(pt1, plaintext) || !bytes.Equal(pt2, plaintext) {
		t.Fatal("both ciphertexts should decrypt correctly")
	}
}

func TestEndToEndKeyDerivation(t *testing.T) {
	// Full flow: code → pairing keys → SPAKE2 → channel keys → encrypt/decrypt
	code := "MYTEST123"
	pairingID, w := derivePairingKeysForWindow(code, 42)

	alice, _ := NewSPAKE2("initiator", w)
	bob, _ := NewSPAKE2("initiator", w)
	bob.Role = "responder"

	keAlice, _ := alice.Finish(bob.PubShare(), pairingID, "alice", "bob")
	keBob, _ := bob.Finish(alice.PubShare(), pairingID, "bob", "alice")

	if !bytes.Equal(keAlice, keBob) {
		t.Fatal("Ke mismatch")
	}

	chA, ekA := DeriveChannelKeys(keAlice, pairingID)
	chB, ekB := DeriveChannelKeys(keBob, pairingID)

	if chA != chB {
		t.Fatal("channelID mismatch")
	}
	if !bytes.Equal(ekA, ekB) {
		t.Fatal("encKey mismatch")
	}

	// Encrypt with alice's key, decrypt with bob's
	msg := []byte("hello from alice")
	ct, _ := Encrypt(ekA, msg, chA)
	pt, err := Decrypt(ekB, ct, chB)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("message mismatch")
	}
}
