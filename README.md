# Fast Mental Poker in Go

An implementation to a two-player version of the [Fast Mental Poker](https://doi.org/10.1515/jmc-2012-0004) protocol in Go,
using secp256r1 and ristretto255.

## Protocol Overview

The FMP protocol has the following operations:
- (Preparation) A and B agrees on a randomized deck, i.e. hashing each card into a point on the curve that is indistinguishable
  from random points. Let the deck be $\{A_i\}$.
- (Shuffle) A shuffles and (commutatively) encrypts the deck, and passes it to B. B does the same thing.
  - Suppose A's key pair is $(x_a, X_a)$. A generates a permutation $\pi_a$, and let the deck be
    $B_i := x_a\cdot A_{\pi_a(i)}$.
- (Shuffle Verification) A uses interaction zero-knowledge proof (ZKP) to show B that $B_i$ is a shuffled encryption of $A_i$.
  Then B does symmetrically.
  - A runs $K$ rounds of ZKP. At $j$-th round, A shuffles and encrypts $B_i$ again with key $y_j$ and $\pi_j$, and commits the result.
    That is, $C_{j,i} := y_j\cdot B_{\pi_j(i)}$
  - B sends a random bit $e$ to A.
  - If $e=0$, A reveals $(y_j, \pi_j)$, which is the path from $B_i$ to $C_{j,i}$.
  - If $e=1$, A reveals $(y_jx_a, \pi_j\circ\pi_a)$, which is the path from $A_i$ to $C_{j,i}$.
- (Drawing) Suppose A needs to draw a card $C$. A sends $h$ to B, lets B decrypts $C$ into $D$.
  And A decrypts the card $D$ and obtains a plain card $A_k$ for some $k$.
  - B needs to use non-interactive ZKP (NI-ZKP) to show that the decryption from $C$ to $D$ is correct.
    Which is, if the generator is $G$, showing the logarithm $X_b / G = C / D$.
  - This can be done with Chaum-Pedersen:
    - B randomly generates a key pair $k, k\cdot G$ and commits two points $R_1 := k\cdot G$ and $R_2 := k\cdot D$.
    - A randomly choose a number $c$ and gives it to B.
    - B computes $s := k - c\cdot x_b$ and gives $s$ to A.
    - A verifies that $R_1 = s\cdot G + c\cdot X_b$ and $R_2 = s\cdot D + c\cdot C$.
- (Opening) A reveals $A_k$ and uses NI-ZKP to show that $X_a / G = D / A_k$.
  The process is the same as Drawing.

## Performance Data

On my Mac (Quad-Core Intel Core i7) with 100 cards and $K=10$, the results are

- ECC in binary
  - Preparation, Shuffle & Verification: 323ms
  - Drawing all 100 cards (total): 60ms
- ECC in wasm (Edge)
  - Preparation, Shuffle & Verification: 12.2s
  - Drawing all 100 cards (total): 2.2s
- Ristretto in binary
  - Preparation, Shuffle & Verification: 213ms
  - Drawing all 100 cards (total): 36ms
- Ristretto in wasm (Edge)
  - Preparation, Shuffle & Verification: 2.3s
  - Drawing all 100 cards (total): 416ms
