package fmp

type MentalPoker[S ScalarT[S], K PrivKeyT[S], C CardT[S, C], SC SchemaT[S, K, C]] struct {
	Schema SC
	NCards int
}

// RollForInitCardList makes local player's roll for InitCardList
func (mp *MentalPoker[S, K, C, SC]) RollForInitCardList() []C {
	ret := make([]C, mp.NCards)
	for i := range ret {
		_, ret[i] = mp.Schema.NewKey()
	}
	return ret
}

// InitCardList returns the initial representation on the card list.
// That is, it randomly hashes cards onto the curve.
func (mp *MentalPoker[S, K, C, SC]) InitCardList(localRoll, remoteRoll []C) []C {
	ret := make([]C, mp.NCards)
	for i := range ret {
		ret[i] = localRoll[i].Add(remoteRoll[i])
	}
	return ret
}

// GenKey generates the key pairs for commutative encryption
func (mp *MentalPoker[S, K, C, SC]) GenKey() (K, C) {
	key, pub := mp.Schema.NewKey()
	return key, pub
}

// ShuffleEncrypt shuffles and encrypts the deck. Returns the permutation and the deck.
func (mp *MentalPoker[S, K, C, SC]) ShuffleEncrypt(input []C, key K) ([]int, []C) {
	shufl := make([]int, mp.NCards)
	for i := range shufl {
		shufl[i] = i
	}
	Shuffle(shufl)
	deck := make([]C, mp.NCards)
	for i, pi := range shufl {
		deck[i] = input[pi].MultScalar(key.Priv())
	}
	return shufl, deck
}

// ShuffleVerifyCommit generates shuffle verification parameters for one round of ZKP
// It generates a new key Xi, shuffles and encrypts deck with Xi and shufl_i into param.
// Returns Xi, shufl_i, param. The local player commits param then.
// Then, the relation is: input --(shufl, key)-> deck --(shufl_i, Xi)-> param
// The opponent randomly requests to reveal in one round
// either deck -> param (shufl_i, Xi)
// or input -> param (shufl * shufl_i, key * Xi)
func (mp *MentalPoker[S, K, C, SC]) ShuffleVerifyCommit(deck []C) (S, []int, []C) {
	xi := mp.Schema.NewRandomScalar()
	shufli := make([]int, mp.NCards)
	for i := range shufli {
		shufli[i] = i
	}
	Shuffle(shufli)
	param := make([]C, mp.NCards)
	for i, pi := range shufli {
		param[i] = deck[pi].MultScalar(xi)
	}
	return xi, shufli, param
}

// ShuffleVerifyReveal reveals (Xi, shufl_i) if req&1 == 0, else (shufl * shufl_i, key * Xi)
func (mp *MentalPoker[S, K, C, SC]) ShuffleVerifyReveal(key K, shufl []int, xi S, shufli []int, req int) (S, []int) {
	if (req & 1) == 0 {
		return xi, shufli
	}
	combined := make([]int, mp.NCards)
	for i, pi := range shufli {
		combined[i] = shufl[pi]
	}
	return key.Priv().MultModN(xi), combined
}

// ShuffleVerifyCheck checks if the parameters given by the opponent passes this round of verification
func (mp *MentalPoker[S, K, C, SC]) ShuffleVerifyCheck(
	input []C, deck []C, param []C, req int, keyi S, shufli []int,
) bool {
	base := input
	if (req & 1) == 0 {
		base = deck
	}
	for i, pi := range shufli {
		card := param[i]
		baseCard := base[pi]
		if !baseCard.MultScalar(keyi).Eq(card) {
			return false
		}
	}
	return true
}

// DecryptCard decrypts an encrypted card
func (mp *MentalPoker[S, K, C, SC]) DecryptCard(key K, card C) C {
	return card.MultScalar(key.Inv())
}

// RevealVerifyCommit is the commit step of reveal verification.
// The local player uses NI-ZKP to show that pubkey / G == card / decrypted
// Here we do Chaum-Pedersen: generate k and commits R1=k*G, R2=k*decrypted to the opponent
// The opponent chooses a random c and gives back.
// Then we gives s = k - c*privKey
// The opponent verifies R1 == s*G + c*pubkey, R2 == s*decrypted + c*card
func (mp *MentalPoker[S, K, C, SC]) RevealVerifyCommit(decrypted C) (S, C, C) {
	k, r1 := mp.Schema.NewKey()
	return k.Priv(), r1, decrypted.MultScalar(k.Priv())
}

// RevealVerifyProof gives the proof (s) based on the c given by the opponent.
func (mp *MentalPoker[S, K, C, SC]) RevealVerifyProof(key K, k S, c S) S {
	return key.Priv().KSubCMulS(k, c)
}

// RevealVerifyCheck checks the proof (s) given by the opponent is correct.
func (mp *MentalPoker[S, K, C, SC]) RevealVerifyCheck(pub C, card C, decrypted C, r1 C, r2 C, c S, s S) bool {
	r1v2 := mp.Schema.BasePoint().MultScalar(s).Add(pub.MultScalar(c))
	r2v2 := decrypted.MultScalar(s).Add(card.MultScalar(c))
	return r1.Eq(r1v2) && r2.Eq(r2v2)
}

type EccMentalPoker = MentalPoker[EccScalar, EccPrivKey, EccCard, EccSchemaType]

func NewEccMentalPoker(NCards int) *EccMentalPoker {
	if NCards > 255 {
		panic("Too many cards (>255)")
	}
	return &EccMentalPoker{
		NCards: NCards,
		Schema: EccSchema,
	}
}
