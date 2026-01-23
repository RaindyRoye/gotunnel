// Package tunnel contains authentication algorithms, including TAA (Tunnel Authentication Algorithm).
package tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand" // Use crypto/rand for secure randomness
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"time"
)

const (
	TaaTokenSize     = aes.BlockSize // Size of the AES block (16 bytes)
	TaaSignatureSize = md5.Size      // Size of the MD5 hash (16 bytes)
	TaaBlockSize     = TaaTokenSize + TaaSignatureSize // Total size of the auth block (32 bytes)
)

// authToken represents the core data for authentication: a challenge and a timestamp.
type authToken struct {
	challenge uint64
	timestamp uint64
}

// toBytes serializes the authToken into a byte slice of size TaaTokenSize (16 bytes).
func (t authToken) toBytes() []byte {
	buf := make([]byte, TaaTokenSize)
	binary.LittleEndian.PutUint64(buf, t.challenge)
	binary.LittleEndian.PutUint64(buf[8:], t.timestamp)
	return buf
}

// fromBytes deserializes a byte slice of size TaaTokenSize (16 bytes) into an authToken.
func (t *authToken) fromBytes(buf []byte) {
	t.challenge = binary.LittleEndian.Uint64(buf)
	t.timestamp = binary.LittleEndian.Uint64(buf[8:])
}

// complement returns a new authToken with both challenge and timestamp bitwise complemented.
func (t authToken) complement() authToken {
	return authToken{
		challenge: ^t.challenge,
		timestamp: ^t.timestamp,
	}
}

// isComplementary checks if the current token is the bitwise complement of another token.
func (t authToken) isComplementary(t1 authToken) bool {
	return t.challenge == ^t1.challenge && t.timestamp == ^t1.timestamp
}

// Taa (Tunnel Authentication Algorithm) handles token generation, signing, and verification.
type Taa struct {
	block cipher.Block // AES cipher block for encryption/decryption
	mac   hash.Hash    // HMAC-MD5 for message authentication
	token authToken    // Current local token state
}

// NewTaa creates a new Taa instance using a string key.
// It derives a 32-byte key using SHA256, then splits it for AES and HMAC.
func NewTaa(key string) *Taa {
	// Derive a 32-byte key from the input string using SHA256.
	token := sha256.Sum256([]byte(key))

	// Initialize AES cipher using the first 16 bytes of the derived key.
	block, err := aes.NewCipher(token[:TaaTokenSize])
	if err != nil {
		// This should not happen with a valid key size (16 bytes for AES-128).
		// Consider logging or handling the error appropriately for your application.
		// For now, we'll panic to indicate a fundamental issue.
		panic("tunnel: failed to create AES cipher: " + err.Error())
	}

	// Initialize HMAC-MD5 using the remaining 16 bytes of the derived key.
	mac := hmac.New(md5.New, token[TaaTokenSize:])

	return &Taa{
		block: block,
		mac:   mac,
	}
}

// GenToken generates a new random challenge and the current timestamp for the local token.
// Uses crypto/rand for cryptographically secure randomness.
func (a *Taa) GenToken() {
	// Generate 8 random bytes for the challenge using crypto/rand
	challengeBytes := make([]byte, 8)
	if _, err := rand.Read(challengeBytes); err != nil {
		// Handling crypto/rand failure is critical. Depending on the application,
		// you might want to return an error, log a fatal error, or retry.
		// For simplicity here, we panic.
		panic("tunnel: failed to generate random challenge: " + err.Error())
	}
	a.token.challenge = binary.LittleEndian.Uint64(challengeBytes)

	// Use the current time in nanoseconds as the timestamp.
	a.token.timestamp = uint64(time.Now().UnixNano())
}

// GenCipherBlock creates an authenticated cipher block from a given token (or the local token if nil).
// The block contains the encrypted token and an HMAC signature.
func (a *Taa) GenCipherBlock(token *authToken) []byte {
	// Use the provided token or fall back to the local token.
	if token == nil {
		token = &a.token
	}

	// Prepare the destination buffer for the cipher block.
	dst := make([]byte, TaaBlockSize)

	// Encrypt the token bytes using AES.
	a.block.Encrypt(dst, token.toBytes())

	// Calculate the HMAC signature over the encrypted token part.
	a.mac.Write(dst[:TaaTokenSize])
	signature := a.mac.Sum(nil)
	a.mac.Reset()

	// Append the signature to the encrypted token in the block.
	copy(dst[TaaTokenSize:], signature)
	return dst
}

// CheckSignature verifies the HMAC signature of a received cipher block.
func (a *Taa) CheckSignature(src []byte) bool {
	// Calculate the expected HMAC over the encrypted token part.
	a.mac.Write(src[:TaaTokenSize])
	expectedMac := a.mac.Sum(nil)
	a.mac.Reset()

	// Compare the calculated MAC with the one present in the block.
	// Uses hmac.Equal to prevent timing attacks.
	return hmac.Equal(src[TaaTokenSize:TaaBlockSize], expectedMac)
}

// ExchangeCipherBlock processes a received cipher block, verifies its signature,
// decrypts the embedded token, updates the local token state, and generates a response block.
func (a *Taa) ExchangeCipherBlock(src []byte) ([]byte, bool) {
	// Validate the block size before processing.
	if len(src) != TaaBlockSize {
		return nil, false
	}

	// Verify the signature first.
	if !a.CheckSignature(src) {
		return nil, false
	}

	// Decrypt the embedded token.
	decryptedBytes := make([]byte, TaaTokenSize)
	a.block.Decrypt(decryptedBytes, src[:TaaTokenSize]) // Only decrypt the first 16 bytes

	// Parse the decrypted bytes into a token.
	var receivedToken authToken
	receivedToken.fromBytes(decryptedBytes)

	// Update the local token state with the received one.
	a.token = receivedToken

	// Generate a response block by encrypting the complement of the received token.
	responseToken := a.token.complement()
	responseBlock := a.GenCipherBlock(&responseToken)

	return responseBlock, true
}

// VerifyCipherBlock processes a received cipher block to verify its authenticity
// against the expected local token. Does not modify the local token state.
func (a *Taa) VerifyCipherBlock(src []byte) bool {
	// Validate the block size before processing.
	if len(src) != TaaBlockSize {
		return false
	}

	// Verify the signature first.
	if !a.CheckSignature(src) {
		return false
	}

	// Decrypt the embedded token.
	decryptedBytes := make([]byte, TaaTokenSize)
	a.block.Decrypt(decryptedBytes, src[:TaaTokenSize]) // Only decrypt the first 16 bytes

	// Parse the decrypted bytes into a token.
	var receivedToken authToken
	receivedToken.fromBytes(decryptedBytes)

	// Check if the received token is the complement of the local token.
	return a.token.isComplementary(receivedToken)
}

// GetChacha20key generates a key for RC4 encryption based on the current local token.
// It repeats the token's byte representation 8 times (resulting in 16 * 8 = 128 bytes).
// Note: RC4 is cryptographically deprecated. This function is preserved as per API requirements.
func (a *Taa) GetChacha20key() []byte {
	return bytes.Repeat(a.token.toBytes(), 8)
}
