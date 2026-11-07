package vm

// AUDIT PoC E - is a value transfer (and other state mutation) revert-immune?
//
// The EVM contract is: if a frame fails (REVERT / out-of-gas / invalid opcode),
// every state change made inside it is rolled back. Here we check that the
// theta transfer performed by the 0xCB precompile is rolled back when the frame
// that performed it reverts. If it is not, the transfer becomes unconditional:
// an attacker contract can drain and then revert, so simulations (eth_call),
// dry-runs, "try/catch" style probes and even failing transactions would all
// leave the money moved.

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
)

// reentryDrainThenRevert builds a contract that
//
//	CALLER == entry -> CALL victim                     (entry path)
//	otherwise       -> <drain drainer> ; REVERT(0,0)    (re-entry path)
func reentryDrainThenRevert(entry, victim, credit common.Address, epilogue string) []byte {
	var b []byte
	app := func(h string) {
		d, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		b = append(b, d...)
	}
	drain := hexBytes(drainerRuntime(credit))

	app("33" + push20hex(entry) + "14") // CALLER == entry ?
	loopOffPos := len(b)
	app("610000") // PUSH2 <loop offset>
	app("57")     // JUMPI

	// re-entry path: drain the frame CallerAddress (the victim), then epilogue
	b = append(b, drain[:len(drain)-1]...) // drainer without trailing STOP
	app(epilogue)

	loopOffset := len(b)
	b[loopOffPos+1] = byte(loopOffset >> 8)
	b[loopOffPos+2] = byte(loopOffset)
	app("5b") // JUMPDEST
	// entry path: CALL(gas, victim, 0, 0, 0, ...)
	app("60006000600060006000")
	app(push20hex(victim))
	app("5a") // GAS
	app("f1") // CALL
	app("00") // STOP
	return b
}

func TestAuditE1_ValueTransferSurvivesRevert(t *testing.T) {
	sv := newAuditView(t)

	setBalance(t, sv, victimCtr, thetaN(100), big.NewInt(0))
	setCode(t, sv, victimCtr, victimCallbackToSender())
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))
	// re-entry path ends with REVERT(0,0)
	setCode(t, sv, attackerCtr, hex.EncodeToString(reentryDrainThenRevert(attackerEOA, victimCtr, attackerEOA, "60006000fd")))

	_, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 4_000_000, big.NewInt(0), big.NewInt(0))

	t.Logf("err               = %v", err)
	t.Logf("victim theta      = %v", thetaOf(sv, victimCtr))
	t.Logf("attacker theta    = %v", thetaOf(sv, attackerEOA))

	if thetaOf(sv, victimCtr).Cmp(thetaN(100)) != 0 {
		t.Fatalf("BUG: value transfer survived the REVERT - victim lost %v", new(big.Int).Sub(thetaN(100), thetaOf(sv, victimCtr)))
	}
}

func TestAuditE2_ValueTransferSurvivesOutOfGas(t *testing.T) {
	sv := newAuditView(t)

	setBalance(t, sv, victimCtr, thetaN(100), big.NewInt(0))
	setCode(t, sv, victimCtr, victimCallbackToSender())
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))
	// epilogue: invalid opcode (0xfe) -> exceptional halt
	setCode(t, sv, attackerCtr, hex.EncodeToString(reentryDrainThenRevert(attackerEOA, victimCtr, attackerEOA, "fe")))

	_, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 4_000_000, big.NewInt(0), big.NewInt(0))

	t.Logf("err               = %v", err)
	t.Logf("victim theta      = %v", thetaOf(sv, victimCtr))
	t.Logf("attacker theta    = %v", thetaOf(sv, attackerEOA))

	if thetaOf(sv, victimCtr).Cmp(thetaN(100)) != 0 {
		t.Fatalf("BUG: value transfer survived an invalid opcode")
	}
}
