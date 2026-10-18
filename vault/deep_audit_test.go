package vault

import (
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/HerodotusTree/grove-network/ledger"
)

func TestAudit_ControlProRataMatchesBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(20261017))
	for i := 0; i < 10000; i++ {
		c := rng.Int63n(math.MaxInt64-1) + 1
		r := rng.Int63n(c)
		a := rng.Int63n(c) + 1
		v := New(ledger.New())
		v.R, v.C = r, c
		want := new(big.Int).Mul(big.NewInt(a), big.NewInt(r))
		want.Quo(want, big.NewInt(c))
		got, err := v.Redeem(a)
		if err != nil || got != want.Int64() || v.R < 0 || v.C < 0 || v.Surplus() < r-c {
			t.Fatalf("iteration %d: R=%d C=%d amount=%d payout=%d want=%s err=%v", i, r, c, a, got, want, err)
		}
	}
}
