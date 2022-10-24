package star

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

// XXX(caw): rename to public config?
type AggregatorConfig interface {
	Splitter() SecretSplitter
	KDF() KDF
	AEAD() KCAEAD
}

type GenericAggregatorConfiguration struct {
	splitter SecretSplitter
	kdf      KDF
	aead     KCAEAD
}

func NewDefaultAggregatorConfiguration() AggregatorConfig {
	kdf := HkdfKDF{crypto.SHA256}
	return GenericAggregatorConfiguration{
		splitter: &FeldmanSplitter{},
		kdf:      kdf,
		aead:     Aes128GcmHmacKCAEAD{kdf: kdf},
	}
}

func (c GenericAggregatorConfiguration) Splitter() SecretSplitter {
	return c.splitter
}

func (c GenericAggregatorConfiguration) KDF() KDF {
	return c.kdf
}

func (c GenericAggregatorConfiguration) AEAD() KCAEAD {
	return c.aead
}

func NewAggregatorConfiguration(splitter SecretSplitter, kdf KDF, aead KCAEAD) AggregatorConfig {
	return GenericAggregatorConfiguration{
		splitter: splitter,
		kdf:      kdf,
		aead:     aead,
	}
}

type Aggregator struct {
	randomizerConfig RandomizerPublicConfig
	config           AggregatorConfig
	reportSets       map[string][]Report
}

func NewAggregator(randomConfig RandomizerPublicConfig, config AggregatorConfig) *Aggregator {
	return &Aggregator{
		randomizerConfig: randomConfig,
		config:           config,
		reportSets:       make(map[string][]Report),
	}
}

type AggregateOutput struct {
	messages       [][]byte
	metadata       [][]byte
	verified       bool
	invalidReports []Report
}

func (a *Aggregator) Consume(report Report) {
	commitmentEnc := hex.EncodeToString(report.randShare.Commitment())
	_, ok := a.reportSets[commitmentEnc]
	if !ok {
		a.reportSets[commitmentEnc] = make([]Report, 0)
	}
	a.reportSets[commitmentEnc] = append(a.reportSets[commitmentEnc], report)
}

func (a Aggregator) AggregateBucket(bucket []byte) (*AggregateOutput, error) {
	reports, ok := a.reportSets[hex.EncodeToString(bucket)]
	if !ok {
		return nil, fmt.Errorf("Invalid bucket ID")
	}

	return a.AggregateReports(reports)
}

func (a Aggregator) AggregateReports(reports []Report) (*AggregateOutput, error) {
	// // Recover the key seed
	// key_seed = Recover(report_set)
	shares := make([]Share, len(reports))
	for i := range reports {
		shares[i] = reports[i].randShare
	}

	// Require that each commitment is identical
	var expectedComitment []byte
	for i := range shares {
		if expectedComitment == nil {
			expectedComitment = shares[i].Commitment()
		} else {
			commitment := shares[i].Commitment()
			if !bytes.Equal(expectedComitment, commitment) {
				return nil, fmt.Errorf("Invalid share set")
			}
		}
	}

	combiner := a.config.Splitter()
	keySeed, err := combiner.Recover(REPORT_THRESHOLD, shares)
	if err != nil {
		return nil, err
	}

	// Derive report encryption randomness
	kdf := a.config.KDF()
	aead := a.config.AEAD()
	key, nonce := deriveEncryptionSecrets(kdf, aead, keySeed)

	client := a.randomizerConfig.NewClient()
	output := &AggregateOutput{
		metadata:       make([][]byte, 0),
		messages:       make([][]byte, 0),
		invalidReports: make([]Report, 0),
		verified:       client.IsVerifiable(),
	}

	// // Decrypt and process each report
	// report_data = Open(key, nonce, nil, ct)
	reportData := make([][]byte, len(reports))
	for i := range reports {
		// Attempt decryption
		reportData[i], err = aead.Open(key, nonce, nil, reports[i].encryptedReport)
		if err != nil {
			log.Println("Report decryption failed:", err)
			output.invalidReports = append(output.invalidReports, reports[i])
			continue
		}

		// Parse out the message and its optional authenticator
		offset := 0
		msgLen := int(binary.BigEndian.Uint32(reportData[i]))
		offset += 4
		msg := reportData[i][offset : offset+msgLen]
		offset += msgLen
		authenticatorLen := int(binary.BigEndian.Uint32(reportData[i][offset:]))
		offset += 4
		authenticator := reportData[i][offset : offset+authenticatorLen]
		offset += authenticatorLen

		// If the authenticator is non-empty, then verify it
		if client.IsVerifiable() {
			rand, err := client.Verify(msg, authenticator)
			if err != nil {
				log.Println("Garbage report detected (message authentication failed):", err)
				output.invalidReports = append(output.invalidReports, reports[i])
				continue
			}

			// Verify that input leads to output based on public function
			shareSecret, _ := deriveShareSecrets(a.config.KDF(), rand)
			derivedKeySeed := a.config.Splitter().EncodeSecret(shareSecret)
			if !bytes.Equal(derivedKeySeed, keySeed) {
				log.Println("Garbage report detected (deterministic key seed derivation mismatch)")
				output.invalidReports = append(output.invalidReports, reports[i])
				continue
			}
		}

		// Parse out the metadata
		metadataLen := int(binary.BigEndian.Uint32(reportData[i][offset:]))
		offset += 4
		metadata := reportData[i][offset : offset+int(metadataLen)]
		offset += int(metadataLen)

		// Validate the report encoding
		if offset != len(reportData[i]) {
			log.Println("Encoding error")
			output.invalidReports = append(output.invalidReports, reports[i])
		}

		// If the report was well-formed, then save its contents into the aggregate report
		output.messages = append(output.messages, make([]byte, msgLen))
		copy(output.messages[len(output.messages)-1], msg)
		output.metadata = append(output.metadata, make([]byte, metadataLen))
		copy(output.metadata[len(output.metadata)-1], metadata)
	}

	return output, nil
}
