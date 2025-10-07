// Code generated from pkg.templ.go. DO NOT EDIT.

// mldsa87 implements NIST signature scheme ML-DSA-87 as defined in FIPS204.
package mldsa87

import (
	"crypto"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"
	"io"

	"github.com/pmurali-sndk/circl/sign"
	common "github.com/pmurali-sndk/circl/sign/internal/dilithium"
	"github.com/pmurali-sndk/circl/sign/mldsa/mldsa87/internal"
)

type SignMode byte

const (
	SignModePure SignMode = iota
	SignModePreHash
)

const (
	// Size of seed for NewKeyFromSeed
	SeedSize = common.SeedSize

	// Size of a packed PublicKey
	PublicKeySize = internal.PublicKeySize

	// Size of a packed PrivateKey
	PrivateKeySize = internal.PrivateKeySize

	// Size of a signature
	SignatureSize = internal.SignatureSize
)

// PublicKey is the type of ML-DSA-87 public key
type PublicKey internal.PublicKey

// PrivateKey is the type of ML-DSA-87 private key
type PrivateKey internal.PrivateKey

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.GenerateKey(rand)
	return (*PublicKey)(pk), (*PrivateKey)(sk), err
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	pk, sk := internal.NewKeyFromSeed(seed)
	return (*PublicKey)(pk), (*PrivateKey)(sk)
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
//
// ctx is the optional context string. Errors if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func signTo(sk *PrivateKey, signMode SignMode, msg, ctx []byte, randomized bool, sig []byte) error {
	var rnd [32]byte
	if randomized {
		_, err := cryptoRand.Read(rnd[:])
		if err != nil {
			return err
		}
	}

	if len(ctx) > 255 {
		return sign.ErrContextTooLong
	}

	internal.SignTo(
		(*internal.PrivateKey)(sk),
		func(w io.Writer) {
			_, _ = w.Write([]byte{byte(signMode)})
			_, _ = w.Write([]byte{byte(len(ctx))})

			if ctx != nil {
				_, _ = w.Write(ctx)
			}
			w.Write(msg)
		},
		rnd,
		sig,
	)
	return nil
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
//
// ctx is the optional context string. Errors if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func SignTo(sk *PrivateKey, msg, ctx []byte, randomized bool, sig []byte) error {
	return signTo(sk, SignModePure, msg, ctx, randomized, sig)
}

// SignHash calculates pre-hash for msg, signs it and writes the signature
// into sig. It will panic if sig is not of length at least SignatureSize.
type SignOpts struct {
	Randomize bool
	PreHash   crypto.Hash
}

// ctx is the optional context string. Fails if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func SignWithOpts(sk *PrivateKey, msg, ctx []byte, opts SignOpts) (sig []byte, err error) {
	sig = make([]byte, SignatureSize)
	signMode := SignModePure
	if opts.PreHash != crypto.Hash(0) {
		msg, err = calculatePrehash(msg, opts.PreHash)
		if err != nil {
			return nil, err
		}
		signMode = SignModePreHash
	}
	if err = signTo(sk, signMode, msg, ctx, opts.Randomize, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// Do not use. Implements ML-DSA.Sign_internal used for compatibility tests.
func (sk *PrivateKey) unsafeSignInternal(msg []byte, rnd [32]byte) []byte {
	var ret [SignatureSize]byte
	internal.SignTo(
		(*internal.PrivateKey)(sk),
		func(w io.Writer) {
			_, _ = w.Write(msg)
		},
		rnd,
		ret[:],
	)
	return ret[:]
}

// Do not use. Implements ML-DSA.Verify_internal used for compatibility tests.
func unsafeVerifyInternal(pk *PublicKey, msg, sig []byte) bool {
	return internal.Verify(
		(*internal.PublicKey)(pk),
		func(w io.Writer) {
			_, _ = w.Write(msg)
		},
		sig,
	)
}

// Verify checks whether the given signature by pk on msg is valid.
//
// ctx is the optional context string. Fails if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func verify(pk *PublicKey, signMode SignMode, msg, ctx, sig []byte) bool {
	if len(ctx) > 255 {
		return false
	}

	return internal.Verify(
		(*internal.PublicKey)(pk),
		func(w io.Writer) {
			_, _ = w.Write([]byte{byte(signMode)})
			_, _ = w.Write([]byte{byte(len(ctx))})

			if ctx != nil {
				_, _ = w.Write(ctx)
			}
			_, _ = w.Write(msg)
		},
		sig,
	)
}

// Verify checks whether the given signature by pk on msg is valid.
//
// ctx is the optional context string. Fails if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func Verify(pk *PublicKey, msg, ctx, sig []byte) bool {
	return verify(pk, SignModePure, msg, ctx, sig)
}

// Verify checks whether the given signature by pk on hash of msg is valid.
type VerifyOpts struct {
	PreHash crypto.Hash
}

// ctx is the optional context string. Fails if ctx is larger than 255 bytes.
// A nil context string is equivalent to an empty context string.
func VerifyWithOpts(pk *PublicKey, msg, ctx, sig []byte, opts VerifyOpts) bool {
	signMode := SignModePure
	if opts.PreHash != crypto.Hash(0) {
		preHash, err := calculatePrehash(msg, opts.PreHash)
		if err != nil {
			return false
		}
		signMode = SignModePreHash
		msg = preHash
	}
	return verify(pk, signMode, msg, ctx, sig)
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Unpack(buf)
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Unpack(buf)
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Pack(buf)
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Pack(buf)
}

// Packs the public key.
func (pk *PublicKey) Bytes() []byte {
	var buf [PublicKeySize]byte
	pk.Pack(&buf)
	return buf[:]
}

// Packs the private key.
func (sk *PrivateKey) Bytes() []byte {
	var buf [PrivateKeySize]byte
	sk.Pack(&buf)
	return buf[:]
}

// Packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// Packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// Unpacks the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of mldsa87.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// Unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of mldsa87.PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}

// Returns seed used to generate PrivateKey, and nil if not retained.
func (sk *PrivateKey) Seed() []byte {
	return (*internal.PrivateKey)(sk).Seed()
}

// Calculate PreHash generates the pre hash of the message using the hash specified
func calculatePrehash(msg []byte, cryptoHash crypto.Hash) ([]byte, error) {
	var oidBytes []byte
	var h hash.Hash
	switch cryptoHash {
	case crypto.SHA256:
		oidBytes, _ = asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
		h = sha256.New()
	case crypto.SHA384:
		oidBytes, _ = asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2})
		h = sha512.New384()
	case crypto.SHA512:
		oidBytes, _ = asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3})
		h = sha512.New()
	case crypto.SHA3_256:
		oidBytes, _ = asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8})
		h = sha3.New256()
	case crypto.SHA3_384:
		oidBytes, _ = asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9})
		h = sha3.New384()
	case crypto.SHA3_512:
		oidBytes, _ = asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10})
		h = sha3.New512()
	default:
		return nil, errors.New("unsupported prehash function")
	}
	h.Write(msg)
	return h.Sum(oidBytes), nil
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	sig []byte, err error) {
	var ret [SignatureSize]byte
	signMode := SignModePure
	if opts.HashFunc() != crypto.Hash(0) {
		msg, err = calculatePrehash(msg, opts.HashFunc())
		if err != nil {
			return nil, err
		}
		signMode = SignModePreHash
	}

	if err = signTo(sk, signMode, msg, nil, false, ret[:]); err != nil {
		return nil, err
	}

	return ret[:], nil
}

// Computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return (*PublicKey)((*internal.PrivateKey)(sk).Public())
}

// Equal returns whether the two private keys equal.
func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return (*internal.PrivateKey)(sk).Equal((*internal.PrivateKey)(castOther))
}

// Equal returns whether the two public keys equal.
func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return (*internal.PublicKey)(pk).Equal((*internal.PublicKey)(castOther))
}

// Boilerplate for generic signatures API

type scheme struct{}

var sch sign.Scheme = &scheme{}

// Scheme returns a generic signature interface for ML-DSA-87.
func Scheme() sign.Scheme { return sch }

func (*scheme) Name() string        { return "ML-DSA-87" }
func (*scheme) PublicKeySize() int  { return PublicKeySize }
func (*scheme) PrivateKeySize() int { return PrivateKeySize }
func (*scheme) SignatureSize() int  { return SignatureSize }
func (*scheme) SeedSize() int       { return SeedSize }

// TODO TLSIdentifier()
func (*scheme) Oid() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
}

func (*scheme) SupportsContext() bool {
	return true
}

func (*scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(nil)
}

func (*scheme) Sign(
	sk sign.PrivateKey,
	msg []byte,
	opts *sign.SignatureOpts,
) []byte {
	var ctx []byte
	sig := make([]byte, SignatureSize)

	priv, ok := sk.(*PrivateKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		ctx = []byte(opts.Context)
	}
	var err error
	if opts != nil && opts.Hash != crypto.Hash(0) {
		sig, err = SignWithOpts(priv, msg, ctx, SignOpts{Randomize: false, PreHash: opts.Hash})
	} else {
		err = SignTo(priv, msg, ctx, false, sig)
	}
	if err != nil {
		panic(err)
	}

	return sig
}

func (*scheme) Verify(
	pk sign.PublicKey,
	msg, sig []byte,
	opts *sign.SignatureOpts,
) bool {
	var ctx []byte
	pub, ok := pk.(*PublicKey)
	if !ok {
		panic(sign.ErrTypeMismatch)
	}
	if opts != nil && opts.Context != "" {
		ctx = []byte(opts.Context)
	}
	if opts != nil && opts.Hash != crypto.Hash(0) {
		return VerifyWithOpts(pub, msg, ctx, sig, VerifyOpts{PreHash: opts.Hash})
	} else {
		return Verify(pub, msg, ctx, sig)
	}
}

func (*scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != SeedSize {
		panic(sign.ErrSeedSize)
	}
	var seed2 [SeedSize]byte
	copy(seed2[:], seed)
	return NewKeyFromSeed(&seed2)
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, sign.ErrPubKeySize
	}

	var (
		buf2 [PublicKeySize]byte
		ret  PublicKey
	)

	copy(buf2[:], buf)
	ret.Unpack(&buf2)
	return &ret, nil
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, sign.ErrPrivKeySize
	}

	var (
		buf2 [PrivateKeySize]byte
		ret  PrivateKey
	)

	copy(buf2[:], buf)
	ret.Unpack(&buf2)
	return &ret, nil
}

func (sk *PrivateKey) Scheme() sign.Scheme {
	return sch
}

func (sk *PublicKey) Scheme() sign.Scheme {
	return sch
}
