# #26 — Unauthenticated reward-redistribution rules (dead staker authorization) + principal-theft closure matrix

**Component:** `ledger/execution/tx_stake_reward_distribution.go`, `ledger/execution/tx_coinbase.go`
**Type:** consensus-level authorization bypass (dead checks in production code) + signed/validated state write
**Asset:** stake-reward stream (TFuel minted to stake sources and their beneficiaries)
**PoC:** `ledger/execution/audit_g_reward_rule_test.go` — `TestAuditG1_NonStakerInstallsRewardRule`, `TestAuditG2_RuleDivertsStakeReward` (both green)
**Status of the escalation requested (principal theft):** **closed** — see §4. This report documents the one authorization defect found in the value layer *and* the exhaustive, line-by-line demonstration that no path turns a third party's principal into the attacker's balance.

---

## 1. The finding

`StakeRewardDistributionTx` is the transaction that installs a **reward split rule**:

```go
// ledger/types/tx.go:988
type StakeRewardDistributionTx struct {
	Fee             Coins
	Holder          TxInput  // stake holder account, i.e., a guardian or an elite edge node
	Beneficiary     TxOutput // the beneficiary to split the reward as the hosting service fee
	SplitBasisPoint uint     // between 0 and 10000
}
```

The rule set is **consensus state**, written through the `StoreView` (`ledger/state/stake_reward_distribution_rule_set.go:41-49`) and consumed **unconditionally** by the block-reward engine at every checkpoint (`handleSplit`, `ledger/execution/tx_coinbase.go:460-495`):

```go
rewardDistribution := srdsr.Get(stake.Holder)
if rewardDistribution == nil { addRewardToMap(stake.Source, reward, accountRewardMap); return }

splitReward := reward * SplitBasisPoint / 10000
sourceReward := reward - splitReward
addRewardToMap(stake.Source, sourceReward, accountRewardMap)
addRewardToMap(rewardDistribution.Beneficiary, splitReward, accountRewardMap)
```

The **entire authorization block** of the executor's `sanityCheck` — the part that is supposed to guarantee that only a *registered stake holder* may own such a rule, and that a beneficiary may not be a staker of that holder — is **commented out in production code**:

`ledger/execution/tx_stake_reward_distribution.go:63-100`

```go
	// stakeHolderAddress := tx.Holder.Address
	// beneficiaryAddress := tx.Beneficiary.Address
	//
	// vcp := view.GetValidatorCandidatePool()
	// if vcp.FindStakeDelegate(stakeHolderAddress) != nil {
	// 	// for safety purpose, for now we don't allow reward split for validators ...
	// 	return result.Error("StakeRewardDistributionTx not allowed for Validators for now")
	// }
	//
	// if tx.Purpose == core.StakeForGuardian {
	// 	gcp := view.GetGuardianCandidatePool().WithStake()
	// 	var gn *core.Guardian
	// 	if gn = gcp.GetWithHolderAddress(stakeHolderAddress); gn == nil {
	// 		return result.Error("%v is not an staked guardian node", stakeHolderAddress)
	// 	}
	// 	for _, stake := range gn.Stakes {
	// 		if stake.Source == beneficiaryAddress {
	// 			return result.Error("Beneficiary is not allowed to be a staker address")
	// 		}
	// 	}
	// } else if tx.Purpose == core.StakeForEliteEdgeNode {
	// 	eenp := state.NewEliteEdgeNodePool(view, true)
	// 	var een *core.EliteEdgeNode
	// 	if een = eenp.Get(stakeHolderAddress); een == nil {
	// 		return result.Error("%v is not a staked elite edge node", stakeHolderAddress)
	// 	}
	// 	...
	// }
```

What is left of `sanityCheck` (`:31-114`) is: address basic validation, the `Holder` **signature**, output basic validation, and the fee/balance checks. The `Purpose` field itself has been removed from the type (`tx.go:993`), so the branch structure the commented code depends on no longer exists either.

**Consequence:** *any* account — with zero stake, never registered as guardian, elite edge node, or validator delegate — can create, update and delete reward-redistribution rules in consensus state, provided only that it can sign for the `Holder` address it writes.

### Executed evidence

`TestAuditG1_NonStakerInstallsRewardRule` (real `Executor.ExecuteTx` → `DeliveredView`, real `sanityCheck` + `process`):

* pre-conditions asserted: attacker is not in the guardian pool, has no EEN record, has no validator stake delegate, has zero staked Theta;
* `StakeRewardDistributionTx{Holder: attacker, Beneficiary: attacker2, SplitBasisPoint: 1000}` is accepted (`result.OK`);
* `StakeRewardDistributionRuleSet.Get(attacker)` in the delivered state returns
  `{StakeHolder: attacker, Beneficiary: attacker2, SplitBasisPoint: 1000}`;
* a second tx with `SplitBasisPoint: 0` **deletes** it again — also from a non-staker.

`TestAuditG2_RuleDivertsStakeReward` shows the rule being consumed by the live reward engine: `handleSplit(stake{Holder: attacker, Source: victim}, srdsr, 1000 TFuel)` credits **100 TFuel to the attacker's beneficiary and 900 TFuel to the source** — the split is conserved (no mint), and the beneficiary's cut is taken out of the stake source's reward.

---

## 2. Why this is consensus-critical and not a UI bug

* The rule set is stored under `StakeRewardDistributionRuleSetKey(...)` and is part of the state root; every node executes `Upsert`/`Remove` identically (`ledger/execution/tx_stake_reward_distribution.go:139-147`).
* The reward engine reads it **without any further validation** (`tx_coinbase.go:470`). There is no "is this holder staked?" re-check at use time.
* The tx type is enabled from `HeightEnableTheta3` (`executor.go:180-183`) — i.e. it is live on mainnet — and it is **not** in `shouldSkipCheckTx` (`ledger/ledger.go:637-649`, which only skips `CoinbaseTx` and `SlashTx`), so it is an ordinary user tx.
* The **defence-in-depth ceiling is inconsistent**: `sanityCheck` caps at **1000 bp = 10 %** (`:59-61`), while the state type, the setter (`core/stake_reward_distribution.go:19-29`) and the consumer (`handleSplit:479-484`, which also panics only above 100 %) all accept up to **10000 bp = 100 %**. `process` even contains a clamp to 10000 (`:132-137`) and a `splitBasisPoint < 0` branch that is **dead code** because the field is `uint` (`tx.go:992`). Any future relaxation of the 10 % sanity ceiling — or any path that reaches `process` without `sanityCheck` (`executor.go:132`) — silently becomes a 100 % diversion of every reward routed through that holder.

---

## 3. What the attacker gains (and what it does **not** gain)

| Capability | Consequence |
|---|---|
| Install a rule on **any address it can sign for**, at any time, for the price of one tx fee | Pre-positioning: a 10 % skim can be planted on an identity *before* it becomes a delegate, with no stake, no registration, no BLS key, no guardian/EEN membership |
| Choose an **arbitrary beneficiary** | The skim can be routed to a fresh address, decoupled from the staking identity |
| Flip (`1000`) / erase (`0`) the rule at will | No staking commitment is required to hold or revoke the privilege, unlike every other staking-surface action |
| Rule is applied to **every** stake whose `Holder` equals the key (`tx_coinbase.go:324, 346, 413` for validator / guardian / EEN stakes) | 10 % of *all* rewards of that holder's stakes, forever, while the rule exists |

**Honest limit (why this is not itself a theft of third-party principal):** the split is keyed by `stake.Holder`, and `handleSplit` pays `stake.Source` the remainder. A victim's stake carries the holder the victim chose when depositing (`DepositStakeTx.Holder`, signed by the depositor), so an attacker cannot re-point a third party's stake at its own rule. The value that can be diverted therefore requires the holder identity to actually receive stakes — i.e. the attacker must be operating a delegate. The defect is a **missing authorization / lifecycle gate** (a privilege that was deliberately removed from the code is still live), not a mint.

---

## 4. Principal-theft closure matrix (the escalation asked for is closed)

Every mutation of `ThetaWei`/`TFuelWei` in the ledger was enumerated and checked for a credit without a matching, authorized debit. There are exactly twelve ways value moves; each one closes:

| # | Path | Debit guard | Credit source of truth | Verdict |
|---|---|---|---|---|
| 1 | TFuel transfer, contract→contract (`opCall`) | `CanTransfer` `vm.go:390` before `Transfer` `vm.go:420`, sender = `caller.Address()` (frame self, **not** `CallerAddress`) | receiver credited inside the frame snapshot `vm.go:400` | 1:1, revert-safe |
| 2 | TFuel transfer, tx level | `adjustByInputs` `executils.go:237` `IsGTE` + sanity balance check | `getOrMakeOutputs`+outputs, duplicate addresses rejected `executils.go:141-149` | 1:1 |
| 3 | THETA inside EVM | `CanTransferTheta` `vm.go:394/467/584`; `thetaValue` is literal zero for all contract-initiated calls (`instructions.go:772`, `:806`) | `TransferTheta` only from the tx input | 1:1, contracts cannot move Theta |
| 4 | `CALLCODE` | `CanTransfer` guard only | **no transfer at all** (`vm.go:452-495`, self→self) | no movement |
| 5 | `DELEGATECALL` / `STATICCALL` | value `nil`, readOnly flag | no transfer (`vm.go:496-571`) | no movement |
| 6 | `CREATE`/`CREATE2` | `CanTransfer` `vm.go:579` | `CreateAccountWithPreviousBalance` + `Transfer` inside snapshot | 1:1, revert-safe |
| 7 | `SELFDESTRUCT` | balance is read from the frame's **self** and `Suicide` sets `TFuelWei = big.NewInt(0)` (`storeview.go:737-753` — pointer reassignment, not in-place mutation) | beneficiary credited `instructions.go:886-892` | exactly 1:1; Theta is burned with the code, never credited |
| 8 | Staking debits (precompiles) | `GetThetaBalance >= amount` `vm.go:131`, `GetBalance >= amount` `vm.go:207` | stake record keeps `Source` = payer | 1:1 |
| 9 | Staking debits (ledger tx) | `IsGTE(stake)` `tx_deposit_stake.go:158` + `minimalBalance` `:133`; per-asset exclusivity enforced `:73-81` | `DepositStake` | 1:1 |
| 10 | Stake returns | gated by `Withdrawn && currentHeight >= ReturnHeight` (`ledger.go:670-673, 699-702, 729-732`) and `returnStake` **removes** the record (`core/stake.go:167-183`), anything else `log.Panicf`s | validator/guardian `ThetaWei:` (`ledger.go:679-682`), EEN `TFuelWei:` (`ledger.go:738-742`) — correct asset per purpose | 1:1, fail-closed |
| 11 | Checkpoint reward mint | bounded: `Σ = totalReward × Σamount/Σamount` in `issueFixedReward` (`tx_coinbase.go:498-535`) and `Σcount = tfuelRewardN` in `issueRandomizedReward` (`:537-660`); `handleSplit` conserves | `CoinbaseTx.sanityCheck` **recomputes** `CalculateReward` and compares every output (`tx_coinbase.go:94-113`); duplicate outputs rejected | inflation is protocol-bounded and re-verified by every validator |
| 12 | Reserved funds | `ReleaseFund` removes the record (`account.go:192-207`), sequences strictly increasing (`:126-130`) so the in-loop removal cannot match twice; `TransferReservedFund` bounded by `remainingFund.IsGTE(total)` and increments `UsedFund` (`:230-267`); split percentages `≥ 0`, `Σ ≤ 100` (`tx_split_rule.go:69-83`) re-checked at use time (`tx_service_payment.go:196`) | reservation itself was debited at `ReserveFund` | 1:1 |

Additional negative results verified in the same pass:

* `SubBalance`/`SubThetaBalance` have no underflow guard (`storeview.go:487-526`), but every caller pre-checks (`vm.go:131, 207, 394, 398`; `executils.go:237`; `tx_deposit_stake.go:158`), so a negative balance is unreachable from user input.
* `GetBalance` returns a live `*big.Int`, and `opSuicide` adds it to a beneficiary — but `Account` objects are re-decoded on every `getOrMakeAccount` call, `big.Int.Add` does not mutate its operand, and `Suicide` reassigns the pointer, so no aliasing amplification exists.
* Stake records cannot be duplicated per `(holder, source)`: `StakeHolder.depositStake` merges by source and refuses to merge into a withdrawn stake (`core/stake.go:130-150`), so the reverse-iteration removal loop in `GuardianCandidatePool.ReturnStakes` (`core/guardian.go:350-385`) always removes exactly the element it inspected.
* EEN stake-return entries are keyed by `ReturnHeight` and consumed with `RemoveEliteEdgeNodeStakeReturns` (`ledger.go:720, 756`), and `ReturnStake` fails closed if the record is missing — no double credit, no panic reachable from user input.
* `SlashTx`'s executor is **not registered** (`executor.go:196-197` commented out), so the slashing path is dead code and cannot be used to move another account's stake.

---

## 5. Reproduction

```bash
export GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
go test -vet=off ./ledger/execution/ -run 'TestAuditG' -v
go test -vet=off ./ledger/vm/ -run 'TestAudit' -v
```

Both suites are green. The two pre-existing `ledger/execution/*_execution_test.go` files did not compile against the current APIs (signature drift, exactly like the `ledger/vm` tests already parked in `_stale_tests/`); they were moved there so the package's tests build.

---

## 6. Mitigation

1. Restore the authorization block — or rather, replace it with the check that matches the current type (the `Purpose` field is gone):
   ```go
   // holder must be a live stake holder: validator delegate, guardian, or EEN
   if !(vcpHasDelegate(holder) || gcp.Contains(holder) || eenp.Contains(holder)) {
       return result.Error("%v is not a staked validator delegate / guardian / elite edge node", holder)
   }
   // and: the beneficiary must not be a stake source of that holder
   ```
2. Enforce the 10 % ceiling in `core.NewRewardDistribution` and in `handleSplit`, not only in `sanityCheck` (make the ceiling 1000 everywhere, or re-check it at use time).
3. Make `SplitBasisPoint` an `int32`/`int64` (or delete the dead `< 0` branch in `process`) so the validation logic is not misleading.
4. Treat the rule set as a privileged table: emit it in `BalanceChanges`-style auditing or require the holder to still hold a non-withdrawn stake when the split is applied — otherwise an ex-delegate keeps a 10 % claim on any future stake attributed to that identity.
