package star

// // Randomness derivation
// rand_prk = Extract(nil, rand)
// key_seed = Expand(rand_prk, "key_seed", 16)
// share_coins = Expand(rand_prk, "share_coins", 16)
func deriveShareSecrets(kdf KDF, rand []byte) ([]byte, []byte) {
	randPrk := kdf.Extract(nil, rand)
	keySeed := kdf.Expand(randPrk, []byte("key_seed"), 16)
	shareCoins := kdf.Expand(randPrk, []byte("share_coins"), 16)
	return keySeed, shareCoins
}

// // Derive report encryption randomness
// key_prk = Extract(nil, key_seed)
// key = Expand(key_prk, "key", Nk)
// nonce = Expand(key_prk, "nonce", Nn)
func deriveEncryptionSecrets(kdf KDF, aead KCAEAD, prk []byte) ([]byte, []byte) {
	keyPrk := kdf.Extract(nil, prk)
	key := kdf.Expand(keyPrk, []byte("key"), aead.Nk())
	nonce := kdf.Expand(keyPrk, []byte("nonce"), aead.Nn())
	return key, nonce
}
