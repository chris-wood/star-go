package star

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"
)

var (
	THRESHOLD     = 10
	CORRUPT_COUNT = 5
	GARBAGE_COUNT = 5
)

func generateReport(client Client, randomizer RandomnessServer, msg, metadata []byte) (Report, error) {
	randomnessContext := client.RandomizeRequest(msg)
	randomnessResponse := randomizer.Evaluate(randomnessContext.req)
	reportContext := randomnessContext.Finalize(randomnessResponse)
	return reportContext.Report(metadata)
}

func generateGarbageReport(client Client, randomizer RandomnessServer, msg, fakeMessage, metadata []byte) (Report, error) {
	randomnessContext := client.RandomizeRequest(msg)
	randomnessResponse := randomizer.Evaluate(randomnessContext.req)
	reportContext := randomnessContext.Finalize(randomnessResponse)
	return reportContext.ReportGarbage(metadata, fakeMessage)
}

func TestSTAR(t *testing.T) {
	var configurations = []struct {
		aggregatorConfig   AggregatorConfig
		randomizerConfig   RandomizerConfig
		validReportCount   int
		corruptReportCount int
		garbageReportCount int
	}{
		{
			NewDefaultAggregatorConfiguration(THRESHOLD),
			NewDefaultRandomizerConfig(),
			THRESHOLD,
			CORRUPT_COUNT,
			0,
		},
		{
			NewDefaultAggregatorConfiguration(THRESHOLD),
			NewBlindRSARandomizerConfig(),
			THRESHOLD,
			CORRUPT_COUNT,
			0,
		},
		{
			NewDefaultAggregatorConfiguration(THRESHOLD),
			NewDefaultRandomizerConfig(),
			THRESHOLD - 1,
			CORRUPT_COUNT,
			0,
		},
		{
			NewDefaultAggregatorConfiguration(THRESHOLD),
			NewBlindRSARandomizerConfig(),
			THRESHOLD,
			0,
			GARBAGE_COUNT,
		},
	}

	for i := range configurations {
		aggregateConfig := configurations[i].aggregatorConfig
		randomizerConfig := configurations[i].randomizerConfig
		validReportCount := configurations[i].validReportCount
		corruptReportCount := configurations[i].corruptReportCount
		garbageReportCount := configurations[i].garbageReportCount

		aggregator := NewAggregator(randomizerConfig.PublicConfig(), aggregateConfig)
		randomizer := randomizerConfig.NewServer()
		client := NewClient(aggregateConfig, randomizerConfig.PublicConfig())

		msg := []byte("msg")
		garbageMessage := []byte("garbage message")
		metadata := []byte("metadata")

		// Run STAR phases 1 and 2 to generate REPORT_THRESHOLD reports
		var err error
		reports := make([]Report, validReportCount+corruptReportCount+garbageReportCount)
		for i := 0; i < validReportCount; i++ {
			reports[i], err = generateReport(client, randomizer, msg, metadata)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Produce some corrupt reports (with invalid shares)
		for i := 0; i < corruptReportCount; i++ {
			reports[i+validReportCount], err = generateReport(client, randomizer, msg, metadata)
			if err != nil {
				t.Fatal(err)
			}
			reports[i+validReportCount].randShare = aggregateConfig.Splitter().RandomShare()
		}

		// Produce some garbage reports (with invalid encrypted messages)
		for i := 0; i < garbageReportCount; i++ {
			reports[i+validReportCount+corruptReportCount], err = generateGarbageReport(client, randomizer, msg, garbageMessage, metadata)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Success should be only be based on the number of valid reports
		expectSuccess := validReportCount >= THRESHOLD

		// Run report through encoding and decoding phase
		encodedReports := make([][]byte, len(reports))
		for i := range reports {
			encodedReports[i] = reports[i].Marshal()
		}
		decodedReports := make([]*Report, 0)
		for i := range encodedReports {
			decodedReports = append(decodedReports, &Report{
				config: aggregateConfig,
			})
			ok := decodedReports[len(decodedReports)-1].Unmarshal(encodedReports[i])
			if !ok {
				t.Log("Report decoding failed")
			}
		}

		// Throw each report at the aggregator
		for i := range decodedReports {
			aggregator.Consume(*decodedReports[i], false)
		}

		// Phase 3: aggregate the bucket
		output, err := aggregator.AggregateBucket(decodedReports[i].randShare.Commitment(), true)
		if expectSuccess && err != nil {
			t.Fatal(err)
		} else if !expectSuccess && err == nil {
			t.Fatal("Expected recovery failure but it did not happen")
		}

		if expectSuccess {
			for i := range output.messages {
				if !bytes.Equal(msg, output.messages[i]) {
					t.Fatal("Message mismatch")
				}
				if !bytes.Equal(output.metadata[i], metadata) {
					t.Fatal("Metadata mismatch")
				}
			}
		}
	}
}

type benchmarkConfig struct {
	name        string
	splitter    SecretSplitter
	kdf         KDF
	aead        KCAEAD
	inputCount  int // Domain size
	inputLen    int // Input length size
	sampleCount int // Population sample size
	threshold   int // Threshold size (typically a fraction of the population sample size)
}

func generateRandomInputs(b *testing.B, count, length int) [][]byte {
	// https://github.com/henrycg/heavyhitters/blob/ddcdc2a736160bfdfb55003ad8059124b13ee73d/src/bin/leader.rs#L48-L72
	randomInputs := make([][]byte, count)
	for i := 0; i < len(randomInputs); i++ {
		generated := false
		for {
			if generated {
				break
			}
			randomInputs[i] = make([]byte, length)
			rand.Reader.Read(randomInputs[i])
			generated = true
			for j := 0; j < i; j++ {
				if bytes.Equal(randomInputs[i], randomInputs[j]) {
					generated = false
				}
			}
		}
	}
	return randomInputs
}

func runBenchmark(b *testing.B, config benchmarkConfig) {
	aggregateConfig := NewAggregatorConfiguration(config.threshold, config.splitter, config.kdf, config.aead)
	randomizerConfig := NewDefaultRandomizerConfig()

	randomInputs := generateRandomInputs(b, config.inputCount, config.inputLen)

	// Pick strings from the set of random inputs according to a Zipf distribution
	// Go: P(k) is proportional to (v + k) ** (-s)          = 1 / (v + k)^s
	// Rust: P(X = k) = H(N,s) * 1 / k^s for k = 1,2,...,N  = H(N,s) / k^s
	source := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	zipf := mrand.NewZipf(source, 1.03, 2.0, uint64(config.inputCount)-1)
	clientInputs := make([][]byte, config.sampleCount)
	for i := 0; i < len(clientInputs); i++ {
		clientInputs[i] = make([]byte, config.inputLen)
		index := zipf.Uint64()
		copy(clientInputs[i], randomInputs[index])
	}

	randomizer := randomizerConfig.NewServer()
	client := NewClient(aggregateConfig, randomizerConfig.PublicConfig())
	fixedMetadata := []byte("")

	name := fmt.Sprintf("%s-%s-%d-%d-%d-%d", aggregateConfig.Name(), randomizerConfig.Name(), config.inputLen, config.inputCount, config.sampleCount, config.threshold)
	fmt.Println(name)

	var err error
	var reports []Report
	b.Run(fmt.Sprintf("(Report-%s)", name), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			reports = make([]Report, config.sampleCount)
			for i := 0; i < config.sampleCount; i++ {
				reports[i], err = generateReport(client, randomizer, clientInputs[i], fixedMetadata)
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run(fmt.Sprintf("(Prepare-%s)", name), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			aggregator := NewAggregator(randomizerConfig.PublicConfig(), aggregateConfig)

			// Consume each report and place them into buckets
			for i := 0; i < config.sampleCount; i++ {
				aggregator.Consume(reports[i], true)
			}
		}
	})

	b.Run(fmt.Sprintf("(Aggregate-%s)", name), func(b *testing.B) {
		rate := float64(0)
		aggregator := NewAggregator(randomizerConfig.PublicConfig(), aggregateConfig)

		// Consume each report and place them into buckets
		for i := 0; i < config.sampleCount; i++ {
			aggregator.Consume(reports[i], true)
		}

		buckets := aggregator.ReadyBuckets()
		for n := 0; n < b.N; n++ {
			// Aggregate each bucket
			aggregateRate := float64(0)
			for i := range buckets {
				bucketSize, err := aggregator.BucketSize(buckets[i])
				if err != nil {
					b.Fatal(err)
				}
				aggregateRate += float64(bucketSize)
				_, err = aggregator.AggregateBucket(buckets[i], false)
				if err != nil {
					b.Fatal(err)
				}
			}
			rate += aggregateRate
		}
		b.ReportMetric(rate/float64(b.N), "rate/op")
	})

	b.Run(fmt.Sprintf("(PrepareAndAggregate-%s)", name), func(b *testing.B) {
		aggregator := NewAggregator(randomizerConfig.PublicConfig(), aggregateConfig)

		// Consume each report and place them into buckets
		for i := 0; i < config.sampleCount; i++ {
			aggregator.Consume(reports[i], false)
		}
		buckets := aggregator.ReadyBuckets()

		rate := float64(0)
		for n := 0; n < b.N; n++ {
			// Aggregate each bucket
			aggregateRate := float64(0)
			for i := range buckets {
				bucketSize, err := aggregator.BucketSize(buckets[i])
				if err != nil {
					b.Fatal(err)
				}
				aggregateRate += float64(bucketSize)
				_, err = aggregator.AggregateBucket(buckets[i], true)
				if err != nil {
					b.Fatal(err)
				}
			}
			rate += aggregateRate
		}
		b.ReportMetric(rate/float64(b.N), "rate/op")
	})
}

func BenchmarkSTAR(b *testing.B) {
	kdf := HkdfKDF{crypto.SHA256}
	feldmanSplitter := &FeldmanSplitter{}
	basicSplitter := &ShamirSplitter{}
	aead := Aes128GcmHmacKCAEAD{kdf: kdf}

	inputLens := []int{32}                               // []int{32, 64, 128, 256, 512}
	inputCounts := []int{128}                            // []int{128, 256, 512, 1024}
	sampleExpansion := []int{2, 4, 6, 8, 10, 12, 14, 16} // []int{2, 4, 8, 16}
	thresholdFractions := []float64{0.001, 0.01, 0.1}    // []int{0.001, 0.01, 0.1, 0.5}

	benchmarkConfigurations := []benchmarkConfig{}
	for i := range inputLens {
		for j := range inputCounts {
			for k := range sampleExpansion {
				for l := range thresholdFractions {
					inputLen := inputLens[i]
					inputCount := inputCounts[j]
					sampleCount := inputCount * sampleExpansion[k]
					threshold := int(thresholdFractions[l] * float64(sampleCount))

					if threshold > 0 {
						benchmarkConfigurations = append(benchmarkConfigurations, benchmarkConfig{
							splitter:    basicSplitter,
							kdf:         kdf,
							aead:        aead,
							inputLen:    inputLen,
							inputCount:  inputCount,
							sampleCount: sampleCount,
							threshold:   threshold,
						})
						benchmarkConfigurations = append(benchmarkConfigurations, benchmarkConfig{
							splitter:    feldmanSplitter,
							kdf:         kdf,
							aead:        aead,
							inputLen:    inputLen,
							inputCount:  inputCount,
							sampleCount: sampleCount,
							threshold:   threshold,
						})
					}
				}
			}
		}
	}

	for i := range benchmarkConfigurations {
		runBenchmark(b, benchmarkConfigurations[i])
	}
}
