package main

import (
	"fmt"
	"time"

	"github.com/zjkmxy/fast-mental-poker/fmp"
)

const (
	N = 100
	K = 10
)

func main() {
	start := time.Now()
	fmpEcc := fmp.NewRistrettoMentalPoker(N)

	// Step 1: A and B randomly hash cards into the curve
	aList := fmpEcc.RollForInitCardList()
	bList := fmpEcc.RollForInitCardList()
	cardList := fmpEcc.InitCardList(aList, bList)

	// Step 2.1 - Shuffle and encrypt (round A)
	aPriv, aPub := fmpEcc.GenKey()
	shuflA, roundA := fmpEcc.ShuffleEncrypt(cardList, aPriv)
	for k := 0; k < K; k++ {
		xi, shufli, parami := fmpEcc.ShuffleVerifyCommit(roundA)
		req := fmp.RandomUint64(2)
		keyi, proofi := fmpEcc.ShuffleVerifyReveal(aPriv, shuflA, xi, shufli, int(req))
		correct := fmpEcc.ShuffleVerifyCheck(cardList, roundA, parami, int(req), keyi, proofi)
		if !correct {
			panic("Verification failed")
		}
	}

	// Step 2.2 - Shuffle and encrypt (round B)
	bPriv, bPub := fmpEcc.GenKey()
	shuflB, roundB := fmpEcc.ShuffleEncrypt(roundA, bPriv)
	for k := 0; k < K; k++ {
		xi, shufli, parami := fmpEcc.ShuffleVerifyCommit(roundB)
		req := fmp.RandomUint64(2)
		keyi, proofi := fmpEcc.ShuffleVerifyReveal(bPriv, shuflB, xi, shufli, int(req))
		correct := fmpEcc.ShuffleVerifyCheck(roundA, roundB, parami, int(req), keyi, proofi)
		if !correct {
			panic("Verification failed")
		}
	}

	deck := roundB

	duration := time.Since(start)
	fmt.Println(duration.String())

	start = time.Now()
	for j := 0; j < N; j += 2 {
		// Step 4.1 - Card draw (A)
		card := deck[j]
		decrypted := fmpEcc.DecryptCard(bPriv, card)
		k, r1, r2 := fmpEcc.RevealVerifyCommit(decrypted)
		c := fmpEcc.Schema.NewRandomScalar()
		s := fmpEcc.RevealVerifyProof(bPriv, k, c)
		correct := fmpEcc.RevealVerifyCheck(bPub, card, decrypted, r1, r2, c, s)
		if !correct {
			panic("Verification failed")
		}

		plainCard := fmpEcc.DecryptCard(aPriv, decrypted)
		flag := false
		for j, v := range cardList {
			if plainCard.Eq(v) {
				flag = true
				fmt.Print("A picked ", j, "\t")
				break
			}
		}
		if !flag {
			panic("unable to find card")
		}

		// Step 4.2 - Card draw (B)
		card = deck[j+1]
		decrypted = fmpEcc.DecryptCard(aPriv, card)
		k, r1, r2 = fmpEcc.RevealVerifyCommit(decrypted)
		c = fmpEcc.Schema.NewRandomScalar()
		s = fmpEcc.RevealVerifyProof(aPriv, k, c)
		correct = fmpEcc.RevealVerifyCheck(aPub, card, decrypted, r1, r2, c, s)
		if !correct {
			panic("Verification failed")
		}

		plainCard = fmpEcc.DecryptCard(bPriv, decrypted)
		flag = false
		for j, v := range cardList {
			if plainCard.Eq(v) {
				flag = true
				fmt.Print("B picked ", j, "\n")
				break
			}
		}
		if !flag {
			panic("unable to find card")
		}
	}

	duration = time.Since(start)
	fmt.Println(duration.String())
}
