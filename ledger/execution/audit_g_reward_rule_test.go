package execution

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/core"
	st "github.com/thetatoken/theta/ledger/state"
	"github.com/thetatoken/theta/ledger/types"
)

// ---------------------------------------------------------------------------------------
// Audit family G: stake-reward-distribution rule authorization.
//
// Finding: the whole authorization block of StakeRewardDistributionTxExecutor.sanityCheck
// is commented out in production code (ledger/execution/tx_stake_reward_distribution.go
// lines 66-100). The only remaining gate is the signature check on tx.Holder, so ANY
// account - with zero stake, and without being a registered guardian / elite edge node /
// validator delegate - can write a reward-redistribution rule into consensus state.
//
// The rule is then consumed unconditionally by handleSplit() in the block-reward engine
// (ledger/execution/tx_coinbase.go:460-495), which diverts SplitBasisPoint/10000 of the
// reward of EVERY stake whose Holder is that address to the rule's beneficiary.
// ---------------------------------------------------------------------------------------

// auditGSetHeight rebuilds the delivered view at the given height. It is the same thing
// execTest.fastforwardTo does, but without LedgerState.Commit(), which needs a dbTagger
// that the test harness passes as nil.
func auditGSetHeight(et *execTest, height uint64) {
	root := et.State().Delivered().Save()
	et.State().ResetState(&core.Block{
		BlockHeader: &core.BlockHeader{Height: height, StateHash: root},
	})
}

// auditGSetAcc stores accounts without going through execTest.SetAcc, which calls
// LedgerState.Commit() and therefore the nil dbTagger of the harness.
func auditGSetAcc(et *execTest, accs ...types.PrivAccount) {
	view := et.State().Delivered()
	for _, acc := range accs {
		view.SetAccount(acc.Account.Address, &acc.Account)
	}
	view.Save()
}

func auditGRuleTestSetup(t *testing.T) (et *execTest, attacker, beneficiary types.PrivAccount, minFee *big.Int) {
	et = NewExecTest()
	// StakeRewardDistributionTx is only supported from HeightEnableTheta3 on.
	auditGSetHeight(et, common.HeightEnableTheta3)

	minFee = types.GetMinimumTransactionFeeTFuelWei(common.HeightEnableTheta3 + 1)

	attacker = types.MakeAcc("audit_g_attacker")
	// types.NewCoins takes int64, which cannot hold the min fee at this height, so build
	// the balance directly.
	attacker.Account.Balance = types.Coins{
		ThetaWei: big.NewInt(0),
		TFuelWei: new(big.Int).Mul(minFee, big.NewInt(1000000)),
	}
	beneficiary = types.MakeAcc("audit_g_beneficiary")
	auditGSetAcc(et, attacker, beneficiary)
	return et, attacker, beneficiary, minFee
}

func auditGMakeRuleTx(et *execTest, attacker types.PrivAccount, beneficiary types.PrivAccount,
	minFee *big.Int, splitBasisPoint uint) *types.StakeRewardDistributionTx {

	tx := &types.StakeRewardDistributionTx{
		Fee: types.Coins{
			ThetaWei: big.NewInt(0),
			TFuelWei: new(big.Int).Mul(minFee, big.NewInt(10)),
		},
		Holder:          types.TxInput{Address: attacker.Address, Sequence: 1}, // theta convention: acc.Sequence + 1
		Beneficiary:     types.TxOutput{Address: beneficiary.Address, Coins: types.NewCoins(0, 0)},
		SplitBasisPoint: splitBasisPoint,
	}
	tx.Holder.Signature = attacker.Sign(tx.SignBytes(et.chainID))
	return tx
}

// G1: a non-staker installs a reward-redistribution rule into consensus state.
func TestAuditG1_NonStakerInstallsRewardRule(t *testing.T) {
	assert := assert.New(t)

	et, attacker, beneficiary, minFee := auditGRuleTestSetup(t)
	view := et.State().Delivered()

	// Pre-conditions: the holder has no stake of any kind and is not a registered node.
	if gcp := view.GetGuardianCandidatePool(); gcp != nil {
		assert.False(gcp.Contains(attacker.Address), "attacker must not be a guardian")
	}
	assert.Nil(st.NewEliteEdgeNodePool(view, true).Get(attacker.Address), "attacker must not be an EEN")
	if vcp := view.GetValidatorCandidatePool(); vcp != nil {
		assert.Nil(vcp.FindStakeDelegate(attacker.Address), "attacker must not be a validator delegate")
		for _, candidate := range vcp.SortedCandidates {
			for _, stake := range candidate.Stakes {
				assert.NotEqual(attacker.Address, stake.Source, "attacker must not have a validator stake")
			}
		}
	}

	tx := auditGMakeRuleTx(et, attacker, beneficiary, minFee, 1000) // 10 %, sanityCheck ceiling
	_, res := et.Executor().ExecuteTx(tx)
	assert.True(res.IsOK(), "sanityCheck/process accepted a reward rule from a non-staker: %v", res)

	// The rule is now committed consensus state, keyed by the attacker's address.
	rd := st.NewStakeRewardDistributionRuleSet(view).Get(attacker.Address)
	assert.NotNil(rd, "reward distribution rule must be present in state")
	assert.Equal(uint(1000), rd.SplitBasisPoint)
	assert.Equal(beneficiary.Address, rd.Beneficiary)
	assert.Equal(attacker.Address, rd.StakeHolder)

	// Removing it again is equally unauthenticated-by-stake: splitBasisPoint 0 deletes.
	tx2 := auditGMakeRuleTx(et, attacker, beneficiary, minFee, 0)
	tx2.Holder.Sequence = 2
	tx2.Holder.Signature = attacker.Sign(tx2.SignBytes(et.chainID))
	_, res2 := et.Executor().ExecuteTx(tx2)
	assert.True(res2.IsOK(), "rule removal accepted: %v", res2)
	assert.Nil(st.NewStakeRewardDistributionRuleSet(view).Get(attacker.Address), "rule must be removed")
}

// G2: the rule written by G1 is consumed verbatim by the live reward engine, diverting
// 10 % of every reward of a stake attributed to the rule's holder address to the
// beneficiary. The split conserves (no mint), i.e. the beneficiary's cut comes out of
// the stake source's reward.
func TestAuditG2_RuleDivertsStakeReward(t *testing.T) {
	assert := assert.New(t)

	et, attacker, beneficiary, minFee := auditGRuleTestSetup(t)
	view := et.State().Delivered()

	tx := auditGMakeRuleTx(et, attacker, beneficiary, minFee, 1000)
	_, res := et.Executor().ExecuteTx(tx)
	assert.True(res.IsOK(), "rule install: %v", res)

	srdsr := st.NewStakeRewardDistributionRuleSet(view)
	assert.NotNil(srdsr.Get(attacker.Address), "rule must be readable by the reward engine")

	// A third party's stake, attributed to the (unstaked) holder that owns the rule.
	victimSource := types.MakeAcc("audit_g_victim_source")
	reward := new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)) // 1,000 TFuel
	stake := &core.Stake{
		Holder: attacker.Address,
		Source: victimSource.Address,
		Amount: new(big.Int).Set(reward),
	}

	accountReward := map[string]types.Coins{}
	handleSplit(stake, srdsr, new(big.Int).Set(reward), &accountReward)

	split := new(big.Int).Div(new(big.Int).Mul(reward, big.NewInt(1000)), big.NewInt(10000)) // 10 %
	rest := new(big.Int).Sub(reward, split)

	sourceReward, ok := accountReward[string(victimSource.Address[:])]
	assert.True(ok, "source must receive the remainder")
	assert.Equal(0, sourceReward.TFuelWei.Cmp(rest), "source loses exactly the split basis points")

	beneficiaryReward, ok := accountReward[string(beneficiary.Address[:])]
	assert.True(ok, "beneficiary must receive the split")
	assert.Equal(0, beneficiaryReward.TFuelWei.Cmp(split), "beneficiary receives the split")

	// conservation: nothing is minted by the split itself
	total := new(big.Int).Add(sourceReward.TFuelWei, beneficiaryReward.TFuelWei)
	assert.Equal(0, total.Cmp(reward), "split must conserve the reward")

	// and with no rule on the holder, the source keeps the whole reward
	srdsr.Remove(attacker.Address)
	accountReward2 := map[string]types.Coins{}
	handleSplit(stake, srdsr, new(big.Int).Set(reward), &accountReward2)
	assert.Equal(0, accountReward2[string(victimSource.Address[:])].TFuelWei.Cmp(reward))

	t.Logf("G2: rule holder=%v beneficiary=%v split=%v TFuel; source keeps %v TFuel",
		attacker.Address.Hex(), beneficiary.Address.Hex(),
		new(big.Float).Quo(new(big.Float).SetInt(split), new(big.Float).SetInt(big.NewInt(1e18))),
		new(big.Float).Quo(new(big.Float).SetInt(rest), new(big.Float).SetInt(big.NewInt(1e18))))
}
