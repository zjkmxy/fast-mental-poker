package fmp

import (
	"crypto/rand"
	"encoding/binary"
)

type PlayerID int

const (
	PlayerA PlayerID = 1
	PlayerB PlayerID = 2
)

func RandomUint64(max uint64) uint64 {
	var n uint64
	binary.Read(rand.Reader, binary.LittleEndian, &n)
	return n % max
}

func Shuffle(slice []int) {
	for i := range slice {
		j := int(RandomUint64(uint64(i + 1)))
		slice[i], slice[j] = slice[j], slice[i]
	}
}

type ScalarT[S any] interface {
	ScalarTrait() ScalarT[S]
	AddModN(S) S
	MultModN(S) S
	InvModN() S
	KSubCMulS(S, S) S
	Bytes() []byte
}

type PrivKeyT[S ScalarT[S]] interface {
	PrivKeyTrait() PrivKeyT[S]
	Priv() S
	Inv() S
}

type CardT[S ScalarT[S], C any] interface {
	CardTrait() CardT[S, C]
	MultScalar(S) C
	Add(C) C
	Eq(C) bool
	Bytes() []byte
}

type SchemaT[S ScalarT[S], K PrivKeyT[S], C CardT[S, C]] interface {
	SchemaTrait() SchemaT[S, K, C]
	NewRandomScalar() S
	NewKey() (K, C)
	ScalarFromBytes([]byte) S
	CardFromBytes([]byte) C
	PubKey(key K) C
	BasePoint() C
}
