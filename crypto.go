package star

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/math/polynomial"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/zk/dleq"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

var (
	aeadAuthenticationError = errors.New("STAR / KCAEAD: authentiation failure")
)

type SecretSplitter interface {
	EmptyShare() Share
	RandomShare() Share
	EncodeSecret(msg []byte) []byte
	Share(k int, msg, randomness []byte) (Share, []byte)
	Recover(k int, shares []Share) ([]byte, error)
}

type ShamirSplitter struct {
}

func hashToField(msg []byte, ctx []byte) group.Scalar {
	// // XXX(spec): we didn't specify the parameters for hash-to-field
	// xmd := expander.NewExpanderMD(crypto.SHA512, []byte("STAR"))
	// us := make([]big.Int, 1)

	// // p = 2^252 + 27742317777372353535851937790883648493
	// // L = ceil((ceil(log2(p)) + k) / 8)
	// // sage: p = 2^252 + 27742317777372353535851937790883648493
	// // sage: k = 128
	// // sage: L = ceil((ceil(log(p, 2)) + k) / 8)
	// // sage: hex(p)
	// // '0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed'
	// // sage: hex(k)
	// // '0x80'
	// // sage: hex(L)
	// // '0x30'

	// // XXX(spec): just use Ristretto's field for Scalars here?
	p := new(big.Int)
	p.SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	// L := uint(0x30)

	// group.HashToField(us, msg, xmd, p, L)
	// ints := make([]*big.Int, len(us))
	// for i := range us {
	// 	ints[i] = &us[i]
	// }

	// scalars := make([]group.Scalar, count)
	// for i := range ints {
	// 	scalars[i] = group.Ristretto255.NewScalar().SetBigInt(ints[i])
	// }

	// return scalars

	// HashToScalar(x, ctx): Implemented by computing SHA-512("FCurve25519" || DST || x) and mapping the output to a Scalar as described in [RISTRETTO], Section 4.4.
	hashInput := []byte("FCurve25519")
	hashInput = append(hashInput, ctx...)
	hashInput = append(hashInput, msg...)
	digest := sha512.Sum512(hashInput)
	value := new(big.Int).SetBytes(digest[:])
	value.Mod(value, p)

	scalar := group.Ristretto255.NewScalar().SetBigInt(value)
	return scalar
}

func commit(m, r group.Scalar) group.Element {
	g := group.Ristretto255.Generator()
	// XXX(spec): specify how this would work (if Pedersen commitments sick around)
	h := group.Ristretto255.HashToElement([]byte("other generator YOLO"), nil)
	gm := group.Ristretto255.NewElement().Mul(g, m)
	hr := group.Ristretto255.NewElement().Mul(h, r)
	c := group.Ristretto255.NewElement().Add(gm, hr)
	return c
}

// XXX(caw): add an "IsValid" function that aggregators can query, or should shares "verify" upon decoding (like ristretto)?
type Share interface {
	InputRaw() *big.Int // XXX(caw): get rid of this once we have a pow(..) like function on the Scalar interface
	Input() group.Scalar
	Output() group.Scalar
	Commitment() []byte

	// BinaryMarshaler returns a byte representation of the scalar.
	encoding.BinaryMarshaler
	// BinaryUnmarshaler recovers a scalar from a byte representation produced
	// by encoding.BinaryMarshaler.
	encoding.BinaryUnmarshaler
}

type ShamirShare struct {
	x          group.Scalar
	y          group.Scalar
	commitment []byte
}

func (s *ShamirShare) Input() group.Scalar {
	return s.x
}

func (s *ShamirShare) InputRaw() *big.Int {
	panic("Never used")
}

func (s *ShamirShare) Output() group.Scalar {
	return s.y
}

func (s *ShamirShare) Commitment() []byte {
	return s.commitment
}

func (s *ShamirShare) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	inputEnc, err := s.Input().MarshalBinary()
	if err != nil {
		return nil, err
	}
	outputEnc, err := s.Output().MarshalBinary()
	if err != nil {
		return nil, err
	}

	b.AddBytes(inputEnc)
	b.AddBytes(outputEnc)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(nil)
	})

	return b.BytesOrPanic(), nil
}

func (s *ShamirShare) MarshalBinaryCompress() ([]byte, error) {
	return s.MarshalBinary()
}

func (s *ShamirShare) UnmarshalBinary(data []byte) error {
	reader := cryptobyte.String(data)

	var input, output []byte
	if !reader.ReadBytes(&input, 32) || !reader.ReadBytes(&output, 32) {
		return fmt.Errorf("Invalid Share encoding")
	}

	inputVal := group.Ristretto255.NewScalar()
	err := inputVal.UnmarshalBinary(input)
	if err != nil {
		return err
	}

	outputVal := group.Ristretto255.NewScalar()
	err = outputVal.UnmarshalBinary(output)
	if err != nil {
		return err
	}

	var commitment cryptobyte.String
	if !reader.ReadUint16LengthPrefixed(&commitment) || !commitment.Empty() {
		return fmt.Errorf("Invalid commitment -- should be empty")
	}

	s.x = inputVal
	s.y = outputVal
	s.commitment = nil

	return nil
}

func (s *ShamirSplitter) EmptyShare() Share {
	return &ShamirShare{}
}

func (s *ShamirSplitter) RandomShare() Share {
	return &ShamirShare{
		x:          group.Ristretto255.RandomScalar(rand.Reader),
		y:          group.Ristretto255.RandomScalar(rand.Reader),
		commitment: nil,
	}
}

func (s *ShamirSplitter) EncodeSecret(secret []byte) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(0))
	dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
	dst = append(dst, buffer...)

	secretCoefficient := hashToField(secret, dst)
	baseEnc, err := secretCoefficient.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return baseEnc
}

func (s *ShamirSplitter) Share(k int, secret, randomness []byte) (Share, []byte) {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(0))
	dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
	dst = append(dst, buffer...)
	secretCoefficient := hashToField(secret, dst)

	coeffs := []group.Scalar{secretCoefficient}
	for i := 0; i < k-1; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i+1))
		dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
		dst = append(dst, buffer...)
		coeffs = append(coeffs, hashToField(randomness, dst))
	}

	poly := polynomial.New(coeffs)
	randomPoint := group.Ristretto255.RandomNonZeroScalar(rand.Reader)
	value := poly.Evaluate(randomPoint)

	baseEnc, err := secretCoefficient.MarshalBinary()
	if err != nil {
		panic(err)
	}

	commitment := sha256.Sum256(secret)

	return &ShamirShare{randomPoint, value, commitment[:]}, baseEnc
}

func (s *ShamirSplitter) Recover(k int, shares []Share) ([]byte, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("Invalid share count")
	}

	xs := make([]group.Scalar, len(shares))
	ys := make([]group.Scalar, len(shares))
	for i := range shares {
		xs[i] = shares[i].Input()
		ys[i] = shares[i].Output()
	}

	l := polynomial.NewLagrangePolynomial(xs, ys)
	zero := group.Ristretto255.NewScalar()

	result := l.Evaluate(zero)
	return result.MarshalBinary()
}

type FeldmanSplitter struct {
}

type FeldmanShare struct {
	r           *big.Int
	x           group.Scalar
	y           group.Scalar
	commitments []group.Element
}

func (s *FeldmanShare) Input() group.Scalar {
	return s.x
}

func (s *FeldmanShare) InputRaw() *big.Int {
	return s.r
}

func (s *FeldmanShare) Output() group.Scalar {
	return s.y
}

func (s *FeldmanShare) Commitment() []byte {
	commitmentEnc := []byte{}
	for i := range s.commitments {
		commitment := s.commitments[i]
		enc, err := commitment.MarshalBinary()
		if err != nil {
			panic(err)
		}
		commitmentEnc = append(commitmentEnc, enc...)
	}

	return commitmentEnc
}

func (s *FeldmanShare) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	inputEnc, err := s.Input().MarshalBinary()
	if err != nil {
		return nil, err
	}
	outputEnc, err := s.Output().MarshalBinary()
	if err != nil {
		return nil, err
	}

	b.AddBytes(inputEnc)
	b.AddBytes(outputEnc)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(s.Commitment())
	})

	return b.BytesOrPanic(), nil
}

func (s *FeldmanShare) MarshalBinaryCompress() ([]byte, error) {
	return s.MarshalBinary()
}

func scalarToBigInt(s group.Scalar) *big.Int {
	sEnc, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	// LE to BE
	for i, j := 0, len(sEnc)-1; i < j; i, j = i+1, j-1 {
		sEnc[i], sEnc[j] = sEnc[j], sEnc[i]
	}

	val := new(big.Int)
	return val.SetBytes(sEnc)
}

func (s *FeldmanShare) UnmarshalBinary(data []byte) error {
	reader := cryptobyte.String(data)

	var input, output []byte
	if !reader.ReadBytes(&input, 32) || !reader.ReadBytes(&output, 32) {
		return fmt.Errorf("Invalid Share encoding")
	}

	inputVal := group.Ristretto255.NewScalar()
	err := inputVal.UnmarshalBinary(input)
	if err != nil {
		return err
	}

	outputVal := group.Ristretto255.NewScalar()
	err = outputVal.UnmarshalBinary(output)
	if err != nil {
		return err
	}

	var commitment cryptobyte.String
	if !reader.ReadUint16LengthPrefixed(&commitment) || commitment.Empty() {
		return fmt.Errorf("Invalid commitment")
	}
	numCommitments := len(commitment) / 32
	s.commitments = make([]group.Element, numCommitments)
	for i := 0; i < numCommitments; i++ {
		s.commitments[i] = group.Ristretto255.NewElement()
		err = s.commitments[i].UnmarshalBinary(commitment[(i * 32) : (i+1)*32])
		if err != nil {
			return err
		}
	}

	// Verify the share upon decoding
	expectedValue := group.Ristretto255.NewElement().MulGen(outputVal) // g^y, y = f(r)
	actualValue := group.Ristretto255.Identity()
	for j := 0; j < numCommitments; j++ {
		num := scalarToBigInt(inputVal)
		power := new(big.Int).Exp(num, new(big.Int).SetInt64(int64(j)), nil)
		p := group.Ristretto255.NewScalar().SetBigInt(power)          // power = pow(r, j)
		t := group.Ristretto255.NewElement().Mul(s.commitments[j], p) // t = commitment^power
		actualValue.Add(actualValue, t)
	}
	if !expectedValue.IsEqual(actualValue) {
		return fmt.Errorf("Invalid share")
	}

	s.x = inputVal
	s.y = outputVal
	s.r = scalarToBigInt(inputVal)

	return nil
}

func (s *FeldmanSplitter) EmptyShare() Share {
	return &FeldmanShare{}
}

func (s *FeldmanSplitter) RandomShare() Share {
	x := group.Ristretto255.RandomScalar(rand.Reader)
	return &FeldmanShare{
		r:           scalarToBigInt(x),
		x:           x,
		y:           group.Ristretto255.RandomScalar(rand.Reader),
		commitments: nil, // XXX(caw): this should take in the threshold so we can generate the appropriate number of commitments
	}
}

func (s *FeldmanSplitter) EncodeSecret(secret []byte) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(0))
	dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
	dst = append(dst, buffer...)
	secretCoefficient := hashToField(secret, dst)
	baseEnc, err := secretCoefficient.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return baseEnc
}

func (s *FeldmanSplitter) Share(k int, msg, randomness []byte) (Share, []byte) {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(0))
	dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
	dst = append(dst, buffer...)
	secret := hashToField(msg, dst)

	// coeffs := append([]group.Scalar{secret}, hashToField(randomness, k-1)...)
	coeffs := []group.Scalar{secret}
	for i := 0; i < k-1; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i+1))
		dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
		dst = append(dst, buffer...)
		coeffs = append(coeffs, hashToField(randomness, dst))
	}
	poly := polynomial.New(coeffs)

	commitments := make([]group.Element, k)
	for i := 0; i < k; i++ {
		commitments[i] = group.Ristretto255.NewElement().MulGen(coeffs[i])
	}

	// XXX(caw): need a better way of sampling a random input point (and its big.Int equivalent), or we need the equivalent of pow() implemented for Scalars
	p := new(big.Int)
	p.SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	r, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic("fixme: make me fallible")
	}
	x := group.Ristretto255.NewScalar().SetBigInt(r)
	y := poly.Evaluate(x)

	baseEnc, err := secret.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return &FeldmanShare{
		r:           r,
		x:           x,
		y:           y,
		commitments: commitments,
	}, baseEnc
}

func (s *FeldmanSplitter) Recover(k int, shares []Share) ([]byte, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("Invalid share count")
	}

	// Recover the commitment elements from the actual commitment
	commitments := make([][]group.Element, len(shares))
	for i := range shares {
		commitments[i] = make([]group.Element, k)
		for j := 0; j < k; j++ {
			commitment := group.Ristretto255.NewElement()
			start := (j * 32)     // sizeof(Ristretto element)
			end := ((j + 1) * 32) // sizeof(Ristretto element)
			err := commitment.UnmarshalBinary(shares[i].Commitment()[start:end])
			if err != nil {
				return nil, err
			}
			commitments[i][j] = commitment
		}
	}

	xs := make([]group.Scalar, len(shares))
	ys := make([]group.Scalar, len(shares))
	for i := range shares {
		expectedValue := group.Ristretto255.NewElement().MulGen(shares[i].Output()) // g^y, y = f(r)
		actualValue := group.Ristretto255.Identity()
		for j := 0; j < k; j++ {
			power := new(big.Int).Exp(shares[i].InputRaw(), new(big.Int).SetInt64(int64(j)), nil)
			p := group.Ristretto255.NewScalar().SetBigInt(power)           // power = pow(r, j)
			t := group.Ristretto255.NewElement().Mul(commitments[i][j], p) // t = commitment^power
			actualValue.Add(actualValue, t)
		}
		if !expectedValue.IsEqual(actualValue) {
			return nil, fmt.Errorf("Verification failed")
		}

		xs[i] = shares[i].Input()
		ys[i] = shares[i].Output()
	}

	l := polynomial.NewLagrangePolynomial(xs, ys)
	zero := group.Ristretto255.NewScalar()

	result := l.Evaluate(zero)
	return result.MarshalBinary()
}

type PedersenSplitter struct {
}

type PedersenShare struct {
	r               *big.Int
	x               group.Scalar
	y1              group.Scalar
	y2              group.Scalar
	polyCommitments []group.Element
}

func (s *PedersenShare) Input() group.Scalar {
	return s.x
}

func (s *PedersenShare) InputRaw() *big.Int {
	return s.r
}

func (s *PedersenShare) Output() group.Scalar {
	return s.y1
}

func (s *PedersenShare) Commitment() []byte {
	commitmentEnc := []byte{}
	for i := range s.polyCommitments {
		commitment := s.polyCommitments[i]
		enc, err := commitment.MarshalBinary()
		if err != nil {
			panic(err)
		}
		commitmentEnc = append(commitmentEnc, enc...)
	}

	return commitmentEnc
}

func (s *PedersenShare) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	inputEnc, err := s.Input().MarshalBinary()
	if err != nil {
		return nil, err
	}
	outputEnc, err := s.Output().MarshalBinary()
	if err != nil {
		return nil, err
	}

	b.AddBytes(inputEnc)
	b.AddBytes(outputEnc)

	return b.BytesOrPanic(), nil
}

func (s *PedersenShare) MarshalBinaryCompress() ([]byte, error) {
	return s.MarshalBinary()
}

func (s *PedersenShare) UnmarshalBinary(data []byte) error {
	reader := cryptobyte.String(data)

	var input, output []byte
	if !reader.ReadBytes(&input, 32) || !reader.ReadBytes(&output, 32) {
		return fmt.Errorf("Invalid Share encoding")
	}

	inputVal := group.Ristretto255.NewScalar()
	err := inputVal.UnmarshalBinary(input)
	if err != nil {
		return err
	}

	outputVal := group.Ristretto255.NewScalar()
	err = outputVal.UnmarshalBinary(output)
	if err != nil {
		return err
	}

	s.x = inputVal
	s.y1 = outputVal
	// XXX(caw): the commitment should probably be encoded as part of the share itself

	return nil
}

func (s *PedersenSplitter) EmptyShare() Share {
	return &PedersenShare{}
}

func (s *PedersenSplitter) RandomShare() Share {
	x := group.Ristretto255.RandomScalar(rand.Reader)
	return &PedersenShare{
		r:               scalarToBigInt(x),
		x:               x,
		y1:              group.Ristretto255.RandomScalar(rand.Reader),
		y2:              group.Ristretto255.RandomScalar(rand.Reader),
		polyCommitments: nil, // XXX(caw): this should take in the threshold so we can generate the appropriate number of commitments
	}
}

func (s *PedersenSplitter) EncodeSecret(secret []byte) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(0))
	dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
	dst = append(dst, buffer...)
	secretCoefficient := hashToField(secret, dst)
	baseEnc, err := secretCoefficient.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return baseEnc
}

func (s *PedersenSplitter) Share(k int, msg, randomness []byte) (Share, []byte) {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(0))
	dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
	dst = append(dst, buffer...)
	secret := hashToField(msg, dst)

	// secret := hashToField(msg, 1)[0]
	t := group.Ristretto255.RandomScalar(rand.Reader)

	// coeffs := append([]group.Scalar{secret}, hashToField(randomness, k-1)...)
	coeffs := []group.Scalar{secret}
	for i := 0; i < k-1; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i+1))
		dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
		dst = append(dst, buffer...)
		coeffs = append(coeffs, hashToField(randomness, dst))
	}
	poly := polynomial.New(coeffs)

	commitSeed := make([]byte, len(randomness))
	copy(commitSeed, randomness)
	commitSeed[0] ^= 0xFF

	// commitCoeffs := append([]group.Scalar{t}, hashToField(commitSeed, k-1)...)
	commitCoeffs := []group.Scalar{t}
	for i := 0; i < k-1; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i+1))
		dst := []byte{0x00, 0x00} //, str(t) || "-" || str(0)
		dst = append(dst, buffer...)
		commitCoeffs = append(commitCoeffs, hashToField(commitSeed, dst))
	}
	polyCommit := polynomial.New(commitCoeffs)

	polyCommitments := make([]group.Element, k)
	for i := 0; i < k; i++ {
		polyCommitments[i] = commit(coeffs[i], commitCoeffs[i])
	}

	// XXX(caw): function for generating random point (and bigInt)
	// XXX(caw): wrap this in a prime-order group abstraction, cribbed from CIRCL for simplicity, to make this implementation self-contained
	p := new(big.Int)
	p.SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	r, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic("fixme: make me fallible")
	}
	x := group.Ristretto255.NewScalar().SetBigInt(r)
	y1 := poly.Evaluate(x)
	y2 := polyCommit.Evaluate(x)

	baseEnc, err := secret.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return &PedersenShare{
		r:               r,
		x:               x,
		y1:              y1,
		y2:              y2,
		polyCommitments: polyCommitments,
	}, baseEnc
}

func (s *PedersenSplitter) Recover(k int, shares []Share) ([]byte, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("Invalid share count")
	}

	// Downcast from Share to PedersenShare, because the abstraction for Share isn't quite right
	pedersenShares := make([]*PedersenShare, len(shares))
	for i := range pedersenShares {
		pedersenShares[i] = shares[i].(*PedersenShare)
	}

	xs := make([]group.Scalar, len(shares))
	ys := make([]group.Scalar, len(shares))
	for i := range shares {
		commitment := commit(pedersenShares[i].y1, pedersenShares[i].y2) // E(s_i, t_i), s_i = F(i) and t_i = G(i)
		actualCommitment := group.Ristretto255.Identity()
		for j := 0; j < k; j++ {
			power := new(big.Int).Exp(pedersenShares[i].r, new(big.Int).SetInt64(int64(j)), nil)
			p := group.Ristretto255.NewScalar().SetBigInt(power)                              // power = pow(r, j)
			t := group.Ristretto255.NewElement().Mul(pedersenShares[i].polyCommitments[j], p) // t = commitment^power
			actualCommitment.Add(actualCommitment, t)
		}
		if !commitment.IsEqual(actualCommitment) {
			return nil, fmt.Errorf("Verification failed")
		}

		xs[i] = pedersenShares[i].x
		ys[i] = pedersenShares[i].y1
	}

	l := polynomial.NewLagrangePolynomial(xs, ys)
	zero := group.Ristretto255.NewScalar()

	result := l.Evaluate(zero)

	return result.MarshalBinary()
}

// XXX(caw): Add a VerifiableRandomnessClient that includes a Verify function
type RandomnessClient interface {
	Blind(element []byte) (RandomnessClientState, []byte)
	IsVerifiable() bool
	Verify(input, authenticator []byte) ([]byte, error)
}

type RandomnessServer interface {
	Evaluate(blindedElement []byte) []byte
}

type BlindRSAClient struct {
	publicKey *rsa.PublicKey
}

func NewBlindRSAClient(publicKey *rsa.PublicKey) BlindRSAClient {
	return BlindRSAClient{publicKey: publicKey}
}

type RandomnessClientState interface {
	Finalize(evaluationResponse []byte) ([]byte, []byte)
}

type BlindRSAClientState struct {
	input    []byte
	verifier blindsign.VerifierState
}

// XXX(caw): make this function fallible
func (r BlindRSAClient) Blind(element []byte) (RandomnessClientState, []byte) {
	verifier := blindrsa.NewDeterministicRSAVerifier(r.publicKey, crypto.SHA512)
	blindedMsg, state, err := verifier.Blind(rand.Reader, element)
	if err != nil {
		panic(err)
	}

	return BlindRSAClientState{
		input:    element,
		verifier: state,
	}, blindedMsg
}

func (r BlindRSAClient) IsVerifiable() bool {
	return true
}

func (r BlindRSAClient) Verify(input, authenticator []byte) ([]byte, error) {
	verifier := blindrsa.NewDeterministicRSAVerifier(r.publicKey, crypto.SHA512)
	err := verifier.Verify(input, authenticator)
	if err != nil {
		return nil, err
	}

	rand := sha512.Sum512(append(input, authenticator...))
	return rand[:], nil
}

// XXX(caw): make this function fallible
func (r BlindRSAClientState) Finalize(evaluationResponse []byte) ([]byte, []byte) {
	sig, err := r.verifier.Finalize(evaluationResponse)
	if err != nil {
		panic(err)
	}

	rand := sha512.Sum512(append(r.input, sig...))
	return rand[:], sig
}

type BlindRSAServer struct {
	privateKey *rsa.PrivateKey
	signer     blindsign.Signer
}

// XXX(caw): make this function fallible
func NewBlindRSAServer(privateKey *rsa.PrivateKey) BlindRSAServer {
	return BlindRSAServer{
		privateKey: privateKey,
		signer:     blindrsa.NewRSASigner(privateKey),
	}
}

// XXX(caw): make this function fallible
func (r BlindRSAServer) Evaluate(blindedElement []byte) []byte {
	blindedSig, err := r.signer.BlindSign(blindedElement)
	if err != nil {
		panic(err)
	}
	return blindedSig
}

type Ristretto255VOPRFClient struct {
	publicKey *oprf.PublicKey
}

func NewRistretto255VOPRFClient(publicKey *oprf.PublicKey) Ristretto255VOPRFClient {
	return Ristretto255VOPRFClient{publicKey: publicKey}
}

type Ristretto255VRandomnessClientState struct {
	input     []byte
	publicKey *oprf.PublicKey
	state     *oprf.FinalizeData
}

// XXX(caw): make this function fallible
func (r Ristretto255VOPRFClient) Blind(element []byte) (RandomnessClientState, []byte) {
	client := oprf.NewVerifiableClient(oprf.SuiteRistretto255, r.publicKey)
	finData, evalReq, err := client.Blind([][]byte{element})
	if err != nil {
		panic(err)
	}

	blindReq := evalReq.Elements[0]
	blindReqEnc, err := blindReq.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return Ristretto255VRandomnessClientState{
		input:     element,
		publicKey: r.publicKey,
		state:     finData,
	}, blindReqEnc
}

func (r Ristretto255VOPRFClient) IsVerifiable() bool {
	return false
}

func (r Ristretto255VOPRFClient) Verify(input, authenticator []byte) ([]byte, error) {
	panic("Non-interactive verification not supported")
}

// XXX(caw): make this function fallible
func (state Ristretto255VRandomnessClientState) Finalize(evaluationResponse []byte) ([]byte, []byte) {
	client := oprf.NewVerifiableClient(oprf.SuiteRistretto255, state.publicKey)

	element := group.Ristretto255.NewElement()
	err := element.UnmarshalBinary(evaluationResponse[:group.Ristretto255.Params().ElementLength])
	if err != nil {
		panic(err)
	}

	proof := &dleq.Proof{}
	err = proof.UnmarshalBinary(group.Ristretto255, evaluationResponse[group.Ristretto255.Params().ElementLength:])
	if err != nil {
		panic(err)
	}

	evaluation := &oprf.Evaluation{
		Elements: []group.Element{element},
		Proof:    proof,
	}

	outputs, err := client.Finalize(state.state, evaluation)
	if err != nil {
		panic(err)
	}

	return outputs[0], nil
}

type Ristretto255VOPRFServer struct {
	privateKey *oprf.PrivateKey
}

// XXX(caw): make this function fallible
func NewRistretto255VOPRFServer(seed, info []byte) Ristretto255VOPRFServer {
	// DeriveKeyPair and return the server
	privateKey, err := oprf.DeriveKey(oprf.SuiteRistretto255, oprf.VerifiableMode, seed, info)
	if err != nil {
		panic(err)
	}

	return Ristretto255VOPRFServer{privateKey: privateKey}
}

// XXX(caw): make this function fallible
func (r Ristretto255VOPRFServer) Evaluate(blindedElement []byte) []byte {
	server := oprf.NewVerifiableServer(oprf.SuiteRistretto255, r.privateKey)

	element := group.Ristretto255.NewElement()
	err := element.UnmarshalBinary(blindedElement)
	if err != nil {
		panic(err)
	}

	req := &oprf.EvaluationRequest{
		Elements: []group.Element{element},
	}

	evaluation, err := server.Evaluate(req)
	if err != nil {
		panic(err)
	}

	evaluatedElement, err := evaluation.Elements[0].MarshalBinary()
	if err != nil {
		panic(err)
	}

	evaluationProof, err := evaluation.Proof.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return append(evaluatedElement, evaluationProof...)
}

type KDF interface {
	Extract(salt, ikm []byte) []byte
	Expand(prk, info []byte, L int) []byte
}

// HKDF-SHA256

type HkdfKDF struct {
	hash crypto.Hash
}

func (f HkdfKDF) Extract(salt, ikm []byte) []byte {
	return hkdf.Extract(f.hash.New, ikm, salt)
}

func (f HkdfKDF) Expand(prk, info []byte, L int) []byte {
	hkdf := hkdf.Expand(f.hash.New, prk, info)
	out := make([]byte, L)
	if _, err := io.ReadFull(hkdf, out); err != nil {
		panic("Extraction failed")
	}
	return out
}

type KCAEAD interface {
	Seal(key, nonce, aad, pt []byte) ([]byte, error)
	Open(key, nonce, aad, ct []byte) ([]byte, error)
	Nk() int
	Nn() int
	Nt() int
}

type Aes128GcmHmacKCAEAD struct {
	kdf KDF
}

// def Seal(key, nonce, aad, pt):
//
//	key_prk = Extract(nil, key)
//	aead_key = Expand(key_prk, "aead", Nk)
//	hmac_key = Expand(key_prk, "hmac", 32) // 32 bytes for SHA-256
//	ct = AES-128-GCM-Seal(key=aead_key, nonce=nonce, aad=aad, pt=pt)
//	tag = HMAC(key=hmac_key, message=ct)
//	return ct || tag
func (c Aes128GcmHmacKCAEAD) Seal(key, nonce, aad, pt []byte) ([]byte, error) {
	keyPrk := c.kdf.Extract(nil, key)
	aeadKey := c.kdf.Expand(keyPrk, []byte("aead"), c.Nk())
	hmacKey := c.kdf.Expand(keyPrk, []byte("hmac"), 32)

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, pt, aad)
	hmac := hmac.New(sha256.New, hmacKey)
	hmac.Write(ct)
	tag := hmac.Sum(nil)

	return append(ct, tag...), nil
}

// def Open(key, nonce, aad, ct_and_tag):
//
//	key_prk = Extract(nil, key)
//	aead_key = Expand(key_prk, "aead", Nk)
//	hmac_key = Expand(key_prk, "hmac", 32) // 32 bytes for SHA-256
//	ct || tag = ct_and_tag
//	expected_tag = HMAC(key=hmac_key, message=ct)
//	if !constant_time_equal(expected_tag, tag):
//	  raise OpenError
//	pt = AES-128-GCM-Open(key=aead_key, nonce=nonce, aad=aad, ct=ct) // This can raise an OpenError
//	return pt
func (c Aes128GcmHmacKCAEAD) Open(key, nonce, aad, ctAndTag []byte) ([]byte, error) {
	keyPrk := c.kdf.Extract(nil, key)
	aeadKey := c.kdf.Expand(keyPrk, []byte("aead"), c.Nk())
	hmacKey := c.kdf.Expand(keyPrk, []byte("hmac"), 32)

	ct := ctAndTag[:len(ctAndTag)-c.Nt()]
	tag := ctAndTag[len(ctAndTag)-c.Nt():]
	hmac := hmac.New(sha256.New, hmacKey)
	hmac.Write(ct)
	expectedTag := hmac.Sum(nil)
	if subtle.ConstantTimeCompare(tag, expectedTag) == 0 {
		return nil, aeadAuthenticationError
	}

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ct, aad)
}

func (c Aes128GcmHmacKCAEAD) Nk() int {
	return 16
}

func (c Aes128GcmHmacKCAEAD) Nn() int {
	return 12
}

func (c Aes128GcmHmacKCAEAD) Nt() int {
	return sha256.New().Size()
}
