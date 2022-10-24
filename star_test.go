package star

import (
	"bytes"
	"testing"
)

var (
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
			NewDefaultAggregatorConfiguration(),
			NewDefaultRandomizerConfig(),
			REPORT_THRESHOLD,
			CORRUPT_COUNT,
			0,
		},
		{
			NewDefaultAggregatorConfiguration(),
			NewBlindRSARandomizerConfig(),
			REPORT_THRESHOLD,
			CORRUPT_COUNT,
			0,
		},
		{
			NewDefaultAggregatorConfiguration(),
			NewDefaultRandomizerConfig(),
			REPORT_THRESHOLD - 1,
			CORRUPT_COUNT,
			0,
		},
		{
			NewDefaultAggregatorConfiguration(),
			NewBlindRSARandomizerConfig(),
			REPORT_THRESHOLD,
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
		expectSuccess := validReportCount >= REPORT_THRESHOLD

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
			aggregator.Consume(*decodedReports[i])
		}

		// Phase 3: aggregate the bucket
		output, err := aggregator.AggregateBucket(decodedReports[i].randShare.Commitment())
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

// XXX(caw): add tests for the following
// - aggregate without the right amount of shares in place
// - classical shamir, invalid share produced (random element)
// - veifiable shamir, invalid share but invalid share set error reported
