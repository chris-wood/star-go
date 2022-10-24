package star

import (
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/cloudflare/circl/oprf"
)

var (
	SEED_LEN_IN_BYTES   = 32
	RSA_KEY_LEN_IN_BITS = 2048
)

type RandomizerConfig interface {
	PublicConfig() RandomizerPublicConfig
	NewServer() RandomnessServer
}

type RandomizerPublicConfig interface {
	NewClient() RandomnessClient
}

type VOPRFRandomizerConfig struct {
	seed []byte
}

type VOPRFRandomizerPublicConfig struct {
	publicKey *oprf.PublicKey
}

func NewDefaultRandomizerConfig() RandomizerConfig {
	seed := make([]byte, SEED_LEN_IN_BYTES)
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}

	return VOPRFRandomizerConfig{
		seed: seed,
	}
}

func (c VOPRFRandomizerPublicConfig) NewClient() RandomnessClient {
	return NewRistretto255VOPRFClient(c.publicKey)
}

func (c VOPRFRandomizerConfig) PublicConfig() RandomizerPublicConfig {
	server := NewRistretto255VOPRFServer(c.seed, []byte("STAR"))
	return VOPRFRandomizerPublicConfig{server.privateKey.Public()}
}

func (c VOPRFRandomizerConfig) NewServer() RandomnessServer {
	return NewRistretto255VOPRFServer(c.seed, []byte("STAR"))
}

type BlindRSARandomizerConfig struct {
	privateKey *rsa.PrivateKey
}

type BlindRSARandomizerPublicConfig struct {
	publicKey *rsa.PublicKey
}

func NewBlindRSARandomizerConfig() BlindRSARandomizerConfig {
	key, err := rsa.GenerateKey(rand.Reader, RSA_KEY_LEN_IN_BITS)
	if err != nil {
		panic(err)
	}

	return BlindRSARandomizerConfig{
		privateKey: key,
	}
}

func (c BlindRSARandomizerPublicConfig) NewClient() RandomnessClient {
	return NewBlindRSAClient(c.publicKey)
}

func (c BlindRSARandomizerConfig) PublicConfig() RandomizerPublicConfig {
	return BlindRSARandomizerPublicConfig{&c.privateKey.PublicKey}
}

func (c BlindRSARandomizerConfig) NewServer() RandomnessServer {
	return NewBlindRSAServer(c.privateKey)
}
