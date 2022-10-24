package star

import "golang.org/x/crypto/cryptobyte"

//	struct {
//		opaque encrypted_report<1..2^16-1>;
//		opaque rand_share<1..2^16-1>;
//		opaque commitment<1..2^16-1>;
//	  } Report;
type Report struct {
	config          AggregatorConfig
	raw             []byte
	encryptedReport []byte
	randShare       Share
	// commitment      []byte
}

func (r *Report) Marshal() []byte {
	if r.raw != nil {
		return r.raw
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(r.encryptedReport)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		shareEnc, err := r.randShare.MarshalBinary()
		if err != nil {
			panic(err)
		}
		b.AddBytes(shareEnc)
	})
	// b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
	// 	b.AddBytes(r.commitment)
	// })
	r.raw = b.BytesOrPanic()

	return r.raw
}

func (r *Report) Unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var encryptedReport cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&encryptedReport) || encryptedReport.Empty() {
		return false
	}

	var randShare cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&randShare) || randShare.Empty() {
		return false
	}

	// var commitment cryptobyte.String
	// if !s.ReadUint16LengthPrefixed(&commitment) || commitment.Empty() {
	// 	return false
	// }

	r.encryptedReport = make([]byte, len(encryptedReport))
	r.randShare = r.config.Splitter().EmptyShare()
	// r.commitment = make([]byte, len(commitment))

	copy(r.encryptedReport, encryptedReport)
	// copy(r.commitment, commitment)
	err := r.randShare.UnmarshalBinary(randShare)
	if err != nil {
		return false
	}

	return true
}
