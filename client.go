package star

import (
	"encoding/binary"
)

type Client struct {
	config       AggregatorConfig
	randomConfig RandomizerPublicConfig
}

type RandomizeContext struct {
	client Client
	state  RandomnessClientState
	msg    []byte
	req    []byte
}

func NewClient(config AggregatorConfig, randomConfig RandomizerPublicConfig) Client {
	return Client{
		config:       config,
		randomConfig: randomConfig,
	}
}

func (c Client) RandomizeRequest(msg []byte) RandomizeContext {
	client := c.randomConfig.NewClient()
	state, req := client.Blind(msg)
	return RandomizeContext{
		client: c,
		msg:    msg,
		state:  state,
		req:    req,
	}
}

type AggregateContext struct {
	client        Client
	msg           []byte
	authenticator []byte
	rand          []byte
}

func (c RandomizeContext) Finalize(response []byte) AggregateContext {
	// rand = client_context.Finalize(msg, blind, evaluated_element)
	rand, authenticator := c.state.Finalize(response)
	return AggregateContext{
		client:        c.client,
		msg:           c.msg,
		authenticator: authenticator,
		rand:          rand,
	}
}

func (c AggregateContext) deriveShareAndSecrets(kdf KDF, aead KCAEAD) (Share, []byte, []byte) {
	// // Randomness derivation
	// rand_prk = Extract(nil, rand)
	// key_seed = Expand(rand_prk, "key_seed", 16)
	// share_coins = Expand(rand_prk, "share_coins", 16)
	shareSecret, shareCoins := deriveShareSecrets(kdf, c.rand)

	// // Share generation
	// rand_share, key_seed, commitment = Share(REPORT_THRESHOLD, TBD, key_seed, share_coins, nil)
	splitter := c.client.config.Splitter()
	randShare, encodedSecret := splitter.Share(c.client.config.Threshold(), shareSecret, shareCoins)

	// // Symmetric encryption key derivation
	// key_prk = Extract(nil, key_seed)
	// key = Expand(key_prk, "key", Nk)
	// nonce = Expand(key_prk, "nonce", Nn)
	key, nonce := deriveEncryptionSecrets(kdf, aead, encodedSecret)

	return randShare, key, nonce
}

func (c AggregateContext) Report(metadata []byte) (Report, error) {
	kdf := c.client.config.KDF()
	aead := c.client.config.AEAD()
	randShare, key, nonce := c.deriveShareAndSecrets(kdf, aead)

	// // Report encryption
	// report_data = len(msg, 4) || msg || len(authenticator, 4) || authenticator || len(aux, 4) || aux
	// encrypted_report = Seal(key, nonce, nil, report_data)
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(len(c.msg)))
	reportData := append(buffer, c.msg...)
	binary.BigEndian.PutUint32(buffer, uint32(len(c.authenticator)))
	reportData = append(reportData, buffer...)
	reportData = append(reportData, c.authenticator...)
	binary.BigEndian.PutUint32(buffer, uint32(len(metadata)))
	reportData = append(reportData, buffer...)
	reportData = append(reportData, metadata...)
	encryptedReport, err := aead.Seal(key, nonce, nil, reportData)
	if err != nil {
		return Report{}, err
	}

	return Report{
		encryptedReport: encryptedReport,
		randShare:       randShare,
	}, nil
}

func (c AggregateContext) ReportGarbage(metadata, garbageMessage []byte) (Report, error) {
	kdf := c.client.config.KDF()
	aead := c.client.config.AEAD()
	randShare, key, nonce := c.deriveShareAndSecrets(kdf, aead)

	// // Report encryption
	// report_data = len(msg, 4) || msg || len(authenticator, 4) || authenticator || len(aux, 4) || aux
	// encrypted_report = Seal(key, nonce, nil, report_data)
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(len(garbageMessage)))
	reportData := append(buffer, garbageMessage...)
	binary.BigEndian.PutUint32(buffer, uint32(len(c.authenticator)))
	reportData = append(reportData, buffer...)
	reportData = append(reportData, c.authenticator...)
	binary.BigEndian.PutUint32(buffer, uint32(len(metadata)))
	reportData = append(reportData, buffer...)
	reportData = append(reportData, metadata...)
	encryptedReport, err := aead.Seal(key, nonce, nil, reportData)
	if err != nil {
		return Report{}, err
	}

	return Report{
		encryptedReport: encryptedReport,
		randShare:       randShare,
	}, nil
}
