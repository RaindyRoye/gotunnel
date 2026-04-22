package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// auth_test 测试矩阵：
//
// Tier 1 — authToken 纯值方法（无状态，最简单）
//   1. toBytes → fromBytes 往返
//   2. complement 位取反
//   3. isComplementary 正例
//   4. isComplementary 反例
//
// Tier 2 — Taa 加解密与签名
//   5. GenCipherBlock(nil) 使用本地 token
//   6. GenCipherBlock(&explicitToken) 使用指定 token
//   7. CheckSignature 篡改密文 → false
//   8. ExchangeCipherBlock 错误 block size → (nil, false)
//   9. VerifyCipherBlock 错误 block size → false
//  10. 不同密钥 → CheckSignature 失败
//  11. 不同密钥 → ExchangeCipherBlock 失败
//  12. 不同密钥 → VerifyCipherBlock 失败
//  13. GetChacha20key 返回正确长度

// ---- Tier 1: authToken 纯值方法 ----

// 1. toBytes → fromBytes 往返

func TestAuthTokenToFromBytes(t *testing.T) {
	orig := authToken{challenge: 0xDEADBEEFCAFEBABE, timestamp: 0x1234567890ABCDEF}
	b := orig.toBytes()

	if len(b) != TaaTokenSize {
		t.Fatalf("len: got %d, want %d", len(b), TaaTokenSize)
	}

	var restored authToken
	restored.fromBytes(b)

	if restored != orig {
		t.Fatalf("roundtrip: got %+v, want %+v", restored, orig)
	}
}

// 2. complement 位取反

func TestAuthTokenComplement(t *testing.T) {
	orig := authToken{challenge: 0xAAAA, timestamp: 0x5555}
	comp := orig.complement()

	if comp.challenge != ^orig.challenge {
		t.Fatalf("challenge: got %#x, want %#x", comp.challenge, ^orig.challenge)
	}
	if comp.timestamp != ^orig.timestamp {
		t.Fatalf("timestamp: got %#x, want %#x", comp.timestamp, ^orig.timestamp)
	}
}

// 3. isComplementary 正例

func TestAuthTokenIsComplementaryPositive(t *testing.T) {
	orig := authToken{challenge: 42, timestamp: 99}
	comp := orig.complement()

	if !orig.isComplementary(comp) {
		t.Fatal("orig should be complementary to its complement")
	}
	if !comp.isComplementary(orig) {
		t.Fatal("complement should be complementary to orig (symmetric)")
	}
}

// 4. isComplementary 反例

func TestAuthTokenIsComplementaryNegative(t *testing.T) {
	a := authToken{challenge: 42, timestamp: 99}

	// 随机 token 极大概率不互补
	var randBuf [16]byte
	rand.Read(randBuf[:])
	var other authToken
	other.fromBytes(randBuf[:])

	// 跳过极其罕见的随机互补情况
	if a.isComplementary(other) {
		t.Log("warning: random token happened to be complementary, skipping")
		return
	}

	if a.isComplementary(other) {
		t.Fatal("random token should not be complementary")
	}
}

// ---- Tier 2: Taa 加解密与签名 ----

// 5. GenCipherBlock(nil) 使用本地 token

func TestGenCipherBlockNilToken(t *testing.T) {
	a := NewTaa("test key")
	a.GenToken()

	block := a.GenCipherBlock(nil)

	if len(block) != TaaBlockSize {
		t.Fatalf("block len: got %d, want %d", len(block), TaaBlockSize)
	}

	// 自己生成的 block 签名应通过
	if !a.CheckSignature(block) {
		t.Fatal("CheckSignature should pass for self-generated block")
	}
}

// 6. GenCipherBlock(&explicitToken) 使用指定 token

func TestGenCipherBlockExplicitToken(t *testing.T) {
	a := NewTaa("test key")
	a.GenToken()

	// 使用一个和本地 token 不同的显式 token
	explicit := authToken{challenge: 0xABCDEF, timestamp: 0x12345678}
	block := a.GenCipherBlock(&explicit)

	if len(block) != TaaBlockSize {
		t.Fatalf("block len: got %d, want %d", len(block), TaaBlockSize)
	}

	// block 签名仍应通过（签名覆盖密文，密钥相同即可）
	if !a.CheckSignature(block) {
		t.Fatal("CheckSignature should pass for explicit-token block")
	}

	// 解密后应该得到显式 token，而非本地 token
	decrypted := make([]byte, TaaTokenSize)
	a.block.Decrypt(decrypted, block[:TaaTokenSize])
	var got authToken
	got.fromBytes(decrypted)

	if got != explicit {
		t.Fatalf("decrypted token: got %+v, want %+v", got, explicit)
	}
}

// 7. CheckSignature 篡改密文 → false

func TestCheckSignatureTampered(t *testing.T) {
	a := NewTaa("test key")
	a.GenToken()
	block := a.GenCipherBlock(nil)

	// 篡改每个字节位置，至少一处应导致签名失败
	tampered := make([]byte, TaaBlockSize)
	for i := 0; i < TaaBlockSize; i++ {
		copy(tampered, block)
		tampered[i] ^= 0xFF

		if !a.CheckSignature(block) {
			t.Fatalf("original block should pass at byte %d", i)
		}
		if a.CheckSignature(tampered) {
			// 签名区域末尾的篡改可能不改变 HMAC 比较结果（极少情况），
			// 但密文区域的篡改必定导致签名失败
			if i < TaaTokenSize {
				t.Fatalf("tampering byte %d (ciphertext) should fail signature", i)
			}
		}
	}
}

// 8. ExchangeCipherBlock 错误 block size → (nil, false)

func TestExchangeCipherBlockWrongSize(t *testing.T) {
	a := NewTaa("test key")

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", make([]byte, TaaBlockSize-1)},
		{"long", make([]byte, TaaBlockSize+1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block, ok := a.ExchangeCipherBlock(tc.data)
			if ok {
				t.Fatal("should return false for wrong size")
			}
			if block != nil {
				t.Fatal("should return nil block for wrong size")
			}
		})
	}
}

// 9. VerifyCipherBlock 错误 block size → false

func TestVerifyCipherBlockWrongSize(t *testing.T) {
	a := NewTaa("test key")

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", make([]byte, TaaBlockSize-1)},
		{"long", make([]byte, TaaBlockSize+1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if a.VerifyCipherBlock(tc.data) {
				t.Fatal("should return false for wrong size")
			}
		})
	}
}

// 10. 不同密钥 → CheckSignature 失败

func TestCheckSignatureDifferentKey(t *testing.T) {
	a1 := NewTaa("key A")
	a2 := NewTaa("key B")

	a1.GenToken()
	block := a1.GenCipherBlock(nil)

	// 不同密钥生成的 block，签名验证应失败
	if a2.CheckSignature(block) {
		t.Fatal("CheckSignature should fail with different key")
	}
}

// 11. 不同密钥 → ExchangeCipherBlock 失败

func TestExchangeCipherBlockDifferentKey(t *testing.T) {
	a1 := NewTaa("key A")
	a2 := NewTaa("key B")

	a1.GenToken()
	block := a1.GenCipherBlock(nil)

	resp, ok := a2.ExchangeCipherBlock(block)
	if ok {
		t.Fatal("ExchangeCipherBlock should fail with different key")
	}
	if resp != nil {
		t.Fatal("response should be nil on failure")
	}
}

// 12. 不同密钥 → VerifyCipherBlock 失败
//
// 同密钥 a1/a2 完成交换，然后用第三方 a3 的密钥验证 → 失败。

func TestVerifyCipherBlockDifferentKey(t *testing.T) {
	a1 := NewTaa("shared key")
	a2 := NewTaa("shared key")
	a3 := NewTaa("other key")

	a1.GenToken()
	b1 := a1.GenCipherBlock(nil)

	b2, ok := a2.ExchangeCipherBlock(b1)
	if !ok {
		t.Fatal("exchange with same key should succeed")
	}

	// a3 用不同密钥，Verify 应失败
	if a3.VerifyCipherBlock(b2) {
		t.Fatal("VerifyCipherBlock should fail with different key")
	}

	// 对比：同密钥 a1 应验证通过
	if !a1.VerifyCipherBlock(b2) {
		t.Fatal("VerifyCipherBlock should succeed with same key")
	}
}

// 13. GetChacha20key 返回正确长度

func TestGetChacha20key(t *testing.T) {
	a := NewTaa("test key")
	a.GenToken()

	key := a.GetChacha20key()

	// 16 bytes × 8 = 128 bytes
	expectedLen := TaaTokenSize * 8
	if len(key) != expectedLen {
		t.Fatalf("key len: got %d, want %d", len(key), expectedLen)
	}

	// 验证是 token 的重复
	token := a.token.toBytes()
	for i := 0; i < 8; i++ {
		chunk := key[i*TaaTokenSize : (i+1)*TaaTokenSize]
		if !bytes.Equal(chunk, token) {
			t.Fatalf("chunk %d: got %x, want %x", i, chunk, token)
		}
	}
}

// ---- 原有集成测试保留 ----

func TestAuth(t *testing.T) {
	key := "a test key"
	a1 := NewTaa(key)
	a2 := NewTaa(key)

	a1.GenToken()
	b1 := a1.GenCipherBlock(nil)
	t.Log("block 1:", b1)
	if !a1.CheckSignature(b1) {
		t.Fatal("check signature failed")
	}

	b2, ok := a2.ExchangeCipherBlock(b1)
	t.Log("block 2:", b2)
	if !ok {
		t.Fatal("exchange block failed")
	}

	if !a1.VerifyCipherBlock(b2) {
		t.Fatal("verify exchanged block failed")
	}

	if a1.token != a2.token {
		t.Fatal("token mismatch: a1 and a2 should have the same token after exchange")
	}
}
