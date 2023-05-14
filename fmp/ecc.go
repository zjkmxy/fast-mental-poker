package fmp

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

var (
	Curve     elliptic.Curve = elliptic.P256()
	EccSchema EccSchemaType  = EccSchemaType{}
)

type EccScalar struct {
	v *big.Int
}

type EccCard struct {
	X, Y *big.Int
}

type EccPrivKey struct {
	key *big.Int
	inv *big.Int
}

type EccSchemaType struct{}

// Priv returns the private key
func (k EccPrivKey) Priv() EccScalar {
	return EccScalar{k.key}
}

// Inv returns the multiplicative inverse of the private key
func (k EccPrivKey) Inv() EccScalar {
	return EccScalar{k.inv}
}

// MultScalar multiplies the card with a scalar
func (c EccCard) MultScalar(s EccScalar) EccCard {
	x, y := Curve.ScalarMult(c.X, c.Y, s.v.Bytes())
	return EccCard{x, y}
}

// Add returns the sum of two cards
func (c EccCard) Add(rhs EccCard) EccCard {
	x, y := Curve.Add(c.X, c.Y, rhs.X, rhs.Y)
	return EccCard{x, y}
}

// Eq returns true if the two cards are the same
func (c EccCard) Eq(rhs EccCard) bool {
	return c.X.Cmp(rhs.X) == 0 || c.Y.Cmp(rhs.Y) == 0
}

// AddModN returns s + rhs
func (s EccScalar) AddModN(rhs EccScalar) EccScalar {
	ret := big.NewInt(0)
	ret.Add(s.v, rhs.v)
	ret.Mod(ret, Curve.Params().N)
	return EccScalar{ret}
}

// MultModN returns s * rhs
func (s EccScalar) MultModN(rhs EccScalar) EccScalar {
	ret := big.NewInt(0)
	ret.Mul(s.v, rhs.v)
	ret.Mod(ret, Curve.Params().N)
	return EccScalar{ret}
}

// InvModN returns s^{-1}
func (s EccScalar) InvModN() EccScalar {
	ret := big.NewInt(0)
	ret.ModInverse(s.v, Curve.Params().N)
	return EccScalar{ret}
}

// KSubCMulS returns (k - c * this), used by Chaum-Pedersen NI-ZKP
func (s EccScalar) KSubCMulS(k, c EccScalar) EccScalar {
	cs := big.NewInt(0).Mul(c.v, s.v)
	kmcs := big.NewInt(0).Sub(k.v, cs)
	return EccScalar{big.NewInt(0).Mod(kmcs, Curve.Params().N)}
}

// NewRandomScalar returns a random scalar
func (EccSchemaType) NewRandomScalar() EccScalar {
	v, _, _, err := elliptic.GenerateKey(Curve, rand.Reader)
	if err != nil {
		panic("Unable to generate random key: " + err.Error())
	}
	return EccScalar{big.NewInt(0).SetBytes(v)}
}

// NewKey returns a pair of new private key and the public key
func (EccSchemaType) NewKey() (EccPrivKey, EccCard) {
	v, x, y, err := elliptic.GenerateKey(Curve, rand.Reader)
	if err != nil {
		panic("Unable to generate random key: " + err.Error())
	}
	priv := EccScalar{big.NewInt(0).SetBytes(v)}
	return EccPrivKey{key: priv.v, inv: priv.InvModN().v}, EccCard{X: x, Y: y}
}

func (s EccScalar) Bytes() []byte {
	return s.v.Bytes()
}

func (EccSchemaType) ScalarFromBytes(v []byte) EccScalar {
	return EccScalar{big.NewInt(0).SetBytes(v)}
}

// Bytes returns the compressed representation of a point (33B)
func (c EccCard) Bytes() []byte {
	return elliptic.MarshalCompressed(Curve, c.X, c.Y)
}

// CardFromBytes unmarshal a card from its byte encryption. Return {nil, nil} if failed.
func (EccSchemaType) CardFromBytes(v []byte) EccCard {
	x, y := elliptic.UnmarshalCompressed(Curve, v)
	return EccCard{X: x, Y: y}
}

func (EccSchemaType) PubKey(key EccPrivKey) EccCard {
	x, y := Curve.ScalarBaseMult(key.key.Bytes())
	return EccCard{X: x, Y: y}
}

func (EccSchemaType) BasePoint() EccCard {
	return EccCard{X: Curve.Params().Gx, Y: Curve.Params().Gy}
}

func (s EccScalar) ScalarTrait() ScalarT[EccScalar] {
	return s
}

func (k EccPrivKey) PrivKeyTrait() PrivKeyT[EccScalar] {
	return k
}

func (c EccCard) CardTrait() CardT[EccScalar, EccCard] {
	return c
}
func (s EccSchemaType) SchemaTrait() SchemaT[EccScalar, EccPrivKey, EccCard] {
	return s
}
