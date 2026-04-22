//
//   date  : 2015-03-06
//   author: xjdrew
//

package tunnel

import "testing"

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
