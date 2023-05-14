package fmp

import (
	"crypto/rand"

	"github.com/oasisprotocol/curve25519-voi/curve"
	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
)

var (
	EdSchema     = EdSchemaType{}
	RisBaseTable = curve.NewRistrettoBasepointTable(curve.RISTRETTO_BASEPOINT_POINT)
)

type EdScalar struct {
	v *scalar.Scalar
}

type EdCard struct {
	v *curve.RistrettoPoint
}

type EdPrivKey struct {
	key *scalar.Scalar
	inv *scalar.Scalar
}

type EdSchemaType struct{}

// Priv returns the private key
func (k EdPrivKey) Priv() EdScalar {
	return EdScalar{k.key}
}

// Inv returns the multiplicative inverse of the private key
func (k EdPrivKey) Inv() EdScalar {
	return EdScalar{k.inv}
}

// MultScalar multiplies the card with a scalar
func (c EdCard) MultScalar(s EdScalar) EdCard {
	ret := curve.NewRistrettoPoint().Mul(c.v, s.v)
	return EdCard{ret}
}

// Add returns the sum of two cards
func (c EdCard) Add(rhs EdCard) EdCard {
	ret := curve.NewRistrettoPoint().Add(c.v, rhs.v)
	return EdCard{ret}
}

// Eq returns true if the two cards are the same
func (c EdCard) Eq(rhs EdCard) bool {
	return c.v.Equal(rhs.v) == 1
}

// AddModN returns s + rhs
func (s EdScalar) AddModN(rhs EdScalar) EdScalar {
	ret := scalar.New()
	ret.Add(s.v, rhs.v)
	return EdScalar{ret}
}

// MultModN returns s * rhs
func (s EdScalar) MultModN(rhs EdScalar) EdScalar {
	ret := scalar.New()
	ret.Mul(s.v, rhs.v)
	return EdScalar{ret}
}

// InvModN returns s^{-1}
func (s EdScalar) InvModN() EdScalar {
	ret := scalar.New()
	ret.Invert(s.v)
	return EdScalar{ret}
}

// KSubCMulS returns (k - c * this), used by Chaum-Pedersen NI-ZKP
func (s EdScalar) KSubCMulS(k, c EdScalar) EdScalar {
	cs := scalar.New().Mul(c.v, s.v)
	kmcs := scalar.New().Sub(k.v, cs)
	return EdScalar{kmcs}
}

// NewRandomScalar returns a random scalar
func (EdSchemaType) NewRandomScalar() EdScalar {
	v, err := scalar.New().SetRandom(rand.Reader)
	if err != nil {
		panic("Unable to generate random key: " + err.Error())
	}
	return EdScalar{v}
}

// NewKey returns a pair of new private key and the public key
func (sc EdSchemaType) NewKey() (EdPrivKey, EdCard) {
	priv := sc.NewRandomScalar()
	inv := priv.InvModN()
	pt := curve.NewRistrettoPoint().MulBasepoint(RisBaseTable, priv.v)
	return EdPrivKey{priv.v, inv.v}, EdCard{pt}
}

func (s EdScalar) Bytes() []byte {
	ret := make([]byte, scalar.ScalarSize)
	s.v.ToBytes(ret)
	return ret
}

func (EdSchemaType) ScalarFromBytes(v []byte) EdScalar {
	ret, err := scalar.NewFromBits(v)
	if err != nil {
		panic("Invalid scalar " + err.Error())
	}
	return EdScalar{ret}
}

// Bytes returns the compressed representation of a point (33B)
func (c EdCard) Bytes() []byte {
	ret, err := c.v.MarshalBinary()
	if err != nil {
		panic("Invalid point " + err.Error())
	}
	return ret
}

// CardFromBytes unmarshal a card from its byte encryption. Return {nil, nil} if failed.
func (EdSchemaType) CardFromBytes(v []byte) EdCard {
	ret := curve.NewRistrettoPoint()
	err := ret.UnmarshalBinary(v)
	if err != nil {
		panic("Invalid point " + err.Error())
	}
	return EdCard{ret}
}

func (EdSchemaType) PubKey(key EdPrivKey) EdCard {
	ret := curve.NewRistrettoPoint().MulBasepoint(RisBaseTable, key.key)
	return EdCard{ret}
}

func (EdSchemaType) BasePoint() EdCard {
	return EdCard{curve.RISTRETTO_BASEPOINT_POINT}
}

func (s EdScalar) ScalarTrait() ScalarT[EdScalar] {
	return s
}

func (k EdPrivKey) PrivKeyTrait() PrivKeyT[EdScalar] {
	return k
}

func (c EdCard) CardTrait() CardT[EdScalar, EdCard] {
	return c
}
func (s EdSchemaType) SchemaTrait() SchemaT[EdScalar, EdPrivKey, EdCard] {
	return s
}
