package latchrelay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// RFC 9382 Section 4: M and N points for P256-SHA256 ciphersuite (compressed form).
// M = 0x02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
// N = 0x03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
var (
	spakeM *spakePoint
	spakeN *spakePoint
	p256   elliptic.Curve
	p256N  *big.Int // curve order
)

type spakePoint struct {
	x, y *big.Int
}

func init() {
	p256 = elliptic.P256()
	p256N = p256.Params().N

	// Decompress M
	mCompressed, _ := hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	mx, my := unmarshalCompressed(p256, mCompressed)
	if mx == nil {
		panic("failed to decompress SPAKE2 M point")
	}
	spakeM = &spakePoint{mx, my}

	// Decompress N
	nCompressed, _ := hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	nx, ny := unmarshalCompressed(p256, nCompressed)
	if nx == nil {
		panic("failed to decompress SPAKE2 N point")
	}
	spakeN = &spakePoint{nx, ny}
}

// unmarshalCompressed decompresses a SEC1 compressed point on the given curve.
func unmarshalCompressed(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
	if len(data) != 33 {
		return nil, nil
	}
	prefix := data[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil
	}

	p := curve.Params().P
	x := new(big.Int).SetBytes(data[1:])

	// y^2 = x^3 - 3x + b (mod p) for P-256
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, p)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, curve.Params().B)
	y2.Mod(y2, p)

	// sqrt using (p+1)/4 since p ≡ 3 mod 4
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, p)

	// Verify
	check := new(big.Int).Mul(y, y)
	check.Mod(check, p)
	if check.Cmp(y2) != 0 {
		return nil, nil
	}

	// Choose correct sign
	if y.Bit(0) != uint(prefix&1) {
		y.Sub(p, y)
	}

	return x, y
}

// DerivePairingKeys derives pairingId and w from a pairing code.
// It tries the current time window first, then the previous window.
func DerivePairingKeys(code string) (pairingID string, w *big.Int) {
	now := time.Now().Unix()
	window := now / 600
	return derivePairingKeysForWindow(code, window)
}

// DerivePairingKeysForWindows returns keys for both current and previous window.
func DerivePairingKeysForWindows(code string) (current, previous struct {
	PairingID string
	W         *big.Int
}) {
	now := time.Now().Unix()
	window := now / 600
	current.PairingID, current.W = derivePairingKeysForWindow(code, window)
	previous.PairingID, previous.W = derivePairingKeysForWindow(code, window-1)
	return
}

func derivePairingKeysForWindow(code string, window int64) (string, *big.Int) {
	code = strings.ToUpper(code)
	salt := fmt.Sprintf("latch-relay-room-v1%d", window)

	seed := pbkdf2.Key([]byte(code), []byte(salt), 100000, 32, sha256.New)

	// pairingId = hex(HKDF-Expand(seed, "roomId", 32))
	roomIDBytes := hkdfExpand(seed, []byte("roomId"), 32)
	pairingID := hex.EncodeToString(roomIDBytes)

	// w = OS2IP(HKDF-Expand(seed, "spake2-w", 48)) mod n
	wBytes := hkdfExpand(seed, []byte("spake2-w"), 48)
	wInt := new(big.Int).SetBytes(wBytes)
	wInt.Mod(wInt, p256N)

	return pairingID, wInt
}

// hkdfExpand performs HKDF-Expand only (no Extract step).
// PRK is used directly as the key for HMAC.
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	t := []byte{}
	counter := byte(1)

	for len(out) < length {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
		counter++
	}

	return out[:length]
}

// SPAKE2State holds the state for one side of a SPAKE2 exchange.
type SPAKE2State struct {
	Role     string // "initiator" or "responder"
	scalar   *big.Int
	pubShare []byte // uncompressed SEC1 (65 bytes)
	w        *big.Int
}

// NewSPAKE2 creates a new SPAKE2 state for the given role and password scalar w.
func NewSPAKE2(role string, w *big.Int) (*SPAKE2State, error) {
	if w == nil || w.Sign() == 0 {
		return nil, fmt.Errorf("w must be non-zero")
	}

	// Generate random scalar x in [1, n-1]
	scalar, err := rand.Int(rand.Reader, new(big.Int).Sub(p256N, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("generate random scalar: %w", err)
	}
	scalar.Add(scalar, big.NewInt(1))

	// Compute x*G
	gx, gy := p256.ScalarBaseMult(scalar.Bytes())

	// Both peers blind with M (pubShare is sent before role assignment)
	wbx, wby := p256.ScalarMult(spakeM.x, spakeM.y, w.Bytes())

	// pubShare = x*G + w*M
	px, py := p256.Add(gx, gy, wbx, wby)

	pubShare := elliptic.Marshal(p256, px, py)

	return &SPAKE2State{
		Role:     role,
		scalar:   scalar,
		pubShare: pubShare,
		w:        w,
	}, nil
}

// PubShare returns the public share (uncompressed SEC1, 65 bytes).
func (s *SPAKE2State) PubShare() []byte {
	return s.pubShare
}

// Finish completes the SPAKE2 exchange given the peer's public share.
// Returns Ke = SHA256(TT).
//
// Both peers blind with M (since pubShare is sent before role assignment).
// Role only affects transcript ordering (pA vs pB).
func (s *SPAKE2State) Finish(peerPubShare []byte, pairingID, myID, peerID string) ([]byte, error) {
	px, py := elliptic.Unmarshal(p256, peerPubShare)
	if px == nil {
		return nil, fmt.Errorf("invalid peer public share")
	}

	// Both peers blinded with M, so always remove w*M
	wbx, wby := p256.ScalarMult(spakeM.x, spakeM.y, s.w.Bytes())

	// Negate: -w*M
	negWby := new(big.Int).Sub(p256.Params().P, wby)

	// peerPub - w*M = peer's scalar*G
	ux, uy := p256.Add(px, py, wbx, negWby)

	// K = scalar * (peerPub - w*M) = scalar * peer_scalar * G
	kx, ky := p256.ScalarMult(ux, uy, s.scalar.Bytes())

	// Build transcript TT
	var pA, pB []byte
	var idProver, idVerifier string
	if s.Role == "initiator" {
		pA = s.pubShare
		pB = peerPubShare
		idProver = myID
		idVerifier = peerID
	} else {
		pA = peerPubShare
		pB = s.pubShare
		idProver = peerID
		idVerifier = myID
	}

	context := "latch-relay-v1" + pairingID
	mUncompressed := elliptic.Marshal(p256, spakeM.x, spakeM.y)
	nUncompressed := elliptic.Marshal(p256, spakeN.x, spakeN.y)
	kUncompressed := elliptic.Marshal(p256, kx, ky)

	tt := buildTT(context, idProver, idVerifier, mUncompressed, nUncompressed, pA, pB, kUncompressed)

	ke := sha256.Sum256(tt)
	return ke[:], nil
}

// buildTT constructs the transcript per RFC 9382.
func buildTT(context, idProver, idVerifier string, m, n, pA, pB, k []byte) []byte {
	var buf []byte

	appendLE := func(data []byte) {
		l := make([]byte, 8)
		binary.LittleEndian.PutUint64(l, uint64(len(data)))
		buf = append(buf, l...)
		buf = append(buf, data...)
	}

	appendLE([]byte(context))
	appendLE([]byte(idProver))
	appendLE([]byte(idVerifier))
	appendLE(m)
	appendLE(n)
	appendLE(pA)
	appendLE(pB)
	appendLE(k)

	return buf
}

// DeriveChannelKeys derives channelId and encKey from Ke and pairingId.
func DeriveChannelKeys(ke []byte, pairingID string) (channelID string, encKey []byte) {
	salt := append([]byte("latch-relay-isk"), []byte(pairingID)...)
	isk := hkdfExtract(salt, ke)

	channelIDBytes := hkdfExpand(isk, []byte("channel"), 32)
	channelID = hex.EncodeToString(channelIDBytes)

	encKey = hkdfExpand(isk, []byte("encrypt"), 32)
	return
}

// hkdfExtract performs HKDF-Extract.
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// ComputeChallengeMac computes the HMAC for challenge-response.
// mac = HMAC-SHA256(encKey, "challenge\0" || channelId || "\0" || nonce || "\0" || id || "\0" || role)
func ComputeChallengeMac(encKey []byte, channelID string, nonce []byte, id, role string) []byte {
	h := hmac.New(sha256.New, encKey)
	h.Write([]byte("challenge"))
	h.Write([]byte{0})
	h.Write([]byte(channelID))
	h.Write([]byte{0})
	h.Write(nonce)
	h.Write([]byte{0})
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(role))
	return h.Sum(nil)
}

// VerifyChallengeMac verifies a challenge MAC.
func VerifyChallengeMac(encKey []byte, channelID string, nonce []byte, id, role string, mac []byte) bool {
	expected := ComputeChallengeMac(encKey, channelID, nonce, id, role)
	return hmac.Equal(expected, mac)
}

// Encrypt encrypts plaintext using AES-256-GCM with the channel's encKey.
// Returns nonce(12B) || ciphertext.
func Encrypt(encKey, plaintext []byte, channelID string) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(channelID))
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts data (nonce || ciphertext) using AES-256-GCM.
func Decrypt(encKey, data []byte, channelID string) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(channelID))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// HKDFDeriveKey is a convenience wrapper for standard HKDF (Extract+Expand).
func HKDFDeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	if _, err := r.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
