package star

import (
	"bytes"
	"crypto"
	"testing"
)

func TestShamir(t *testing.T) {
	k := 3
	msg := []byte("msg")
	randomness := []byte("randomness")

	splitter := ShamirSplitter{}

	share1, secretShare := splitter.Share(k, msg, randomness)
	share2, _ := splitter.Share(k, msg, randomness)
	share3, _ := splitter.Share(k, msg, randomness)
	shares := []Share{share1, share2, share3}

	recovered, err := splitter.Recover(k, shares)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretShare, recovered) {
		t.Fatal("Recovery mismatch")
	}
}

func TestPedersenVSS(t *testing.T) {
	k := 3
	msg := []byte("msg")
	randomness := []byte("randomness")

	splitter := PedersenSplitter{}

	share1, secretShare := splitter.Share(k, msg, randomness)
	share2, _ := splitter.Share(k, msg, randomness)
	share3, _ := splitter.Share(k, msg, randomness)
	shares := []Share{share1, share2, share3}

	recovered, err := splitter.Recover(k, shares)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretShare, recovered) {
		t.Fatal("Recovery mismatch")
	}
}

func TestFeldmanVSS(t *testing.T) {
	k := 3
	msg := []byte("msg")
	randomness := []byte("randomness")

	splitter := FeldmanSplitter{}
	share1, secretShare := splitter.Share(k, msg, randomness)
	share2, _ := splitter.Share(k, msg, randomness)
	share3, _ := splitter.Share(k, msg, randomness)
	shares := []Share{share1, share2, share3}

	// Assert that each commitment is the same
	expectedCommitment := shares[0].Commitment()
	for i := 1; i < len(shares); i++ {
		commitment := shares[i].Commitment()
		if !bytes.Equal(commitment, expectedCommitment) {
			t.Fatal("Mismatched commitments")
		}
	}

	recovered, err := splitter.Recover(k, shares)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretShare, recovered) {
		t.Fatal("Recovery mismatch")
	}
}

func TestAEAD(t *testing.T) {
	aead := Aes128GcmHmacKCAEAD{kdf: HkdfKDF{crypto.SHA256}}
	key := make([]byte, aead.Nk())
	nonce := make([]byte, aead.Nn())
	msg := []byte("hello world")
	aad := []byte("aad")

	ct, err := aead.Seal(key, nonce, aad, msg)
	if err != nil {
		t.Fatal("Seal failed", err)
	}
	pt, err := aead.Open(key, nonce, aad, ct)
	if err != nil {
		t.Fatal("Open failed", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("Recovery mismatch")
	}
}
