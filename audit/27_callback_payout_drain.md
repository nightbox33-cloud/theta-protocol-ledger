# #27 — Callback-payout drain: any outbound call to an attacker address confiscates the caller's whole TFuel balance

**Component:** `0xCE` (`stakeToEEN`) precompile + `Contract.AsDelegate` + `StakeToEEN`
**Trigger class:** a contract that performs a single outgoing call to an address the attacker controls — `claim()`, `refund()`, `notify()`, `onTokenTransfer()`-style hooks, zero-value pings included
**PoC:** `ledger/vm/audit_h_callback_payout_test.go` — `TestAuditH1_ClaimPayoutDrainsPayerTFuel`, `TestAuditH2_CapBypassDrains137MTFuelInOneTx`, `TestAuditH3_ZeroValueHookIsEnough` (all green)
**Status of the sTFuel NodeManager instance (≈1.37M TFuel):** **UNVERIFIED from this environment** — see §4. What *is* verified is the complete mechanism and the fact that the per-EEN 500k cap does not bound it.

---

## 0. Verdict on the hypothesis

| Claim | Verdict |
|---|---|
| `0xCE` debits TFuel from `contract.CallerAddress` | **CONFIRMED**, exact lines in §1 |
| In a delegatecall frame `CallerAddress` is the frame's *caller* (i.e. the victim that called the attacker) | **CONFIRMED**, `contract.go:121-130` |
| A payout to `msg.sender` from a contract lets the attacker run code in a frame whose `CallerAddress` is that contract | **CONFIRMED by execution** (H1) |
| The whole balance of the payer is taken (not just the reward) | **CONFIRMED by execution**: 250,000 TFuel → 0, stake 249,999.999… TFuel |
| The 500,000 TFuel per-EEN cap limits the theft | **REFUTED by execution** (H2): 1,370,000 TFuel drained in one tx across 3 EENs |
| Value must be transferred (a "payout") | **REFUTED by execution** (H3): a **zero-value** hook is enough |
| Whether the reward is deducted before or after the callback matters | **NO** — the attacker reads the live balance with `BALANCE`; H1 deducts the reward first and still takes everything left |
| The attacker **keeps** the 1.37M TFuel | **CORRECTED** — the stake's `Source` is the victim, so the principal is *confiscated and immobilized*, not transferred to the attacker; his direct take is the yield (§5) |
| The NodeManager really is a `call{value}` payout with ~1.37M TFuel | **NOT VERIFIED HERE** — see §4 (and the 2,300-gas caveat, which is decisive) |

---

## 1. The code chain (unmodified production code)

```
ledger/vm/contracts.go:104      callerAddr := contract.CallerAddress
ledger/vm/contracts.go:519      ok := StakeToEEN(evm.StateDB, callerAddr, summary, tfuelWeiAmount)
ledger/vm/contracts.go:520-521  (input layout: summary at 0..229, amount at 261..293)

ledger/vm/contract.go:66-67     NewContract(caller, object, ...) -> CallerAddress: caller.Address()
ledger/vm/contract.go:121-130    func (c *Contract) AsDelegate() *Contract {
                                    parent := c.caller.(*Contract)
                                    c.CallerAddress = parent.CallerAddress   // <-- the leak
                                }

ledger/vm/vm.go:496-527         EVM.DelegateCall: NewContract(caller, AccountRef(caller.Address()), nil, nil, gas).AsDelegate()
ledger/vm/vm.go:203             if db.GetBalance(sender).Cmp(amount) < 0 { return false }
ledger/vm/vm.go:207             (BLS ownership proof skipped when the EEN already exists)
ledger/vm/vm.go:216             db.SubBalance(sender, amount)
ledger/state/elite_edge_node_pool.go:216-223   per-deposit limits 10,000 .. 500,000 TFuel,
                                               and currentStake+amount <= 500,000
ledger/vm/params/protocol_params.go:102        StakeToGuardianGas = 21,000 (also used by 0xCE)
```

Frame sequence of the attack:

```
EOA ──CALL──▶ attacker contract                     CallerAddress = EOA
              │  (its code calls the victim's claim())
              ▼
victim contract                                     CallerAddress = attacker contract
              │  claim(): CALL{value: reward}(msg.sender)   <-- attacker contract
              ▼
attacker contract (fallback)                        CallerAddress = VICTIM
              │  DELEGATECALL 0xCE  (AsDelegate keeps CallerAddress = VICTIM)
              ▼
StakeToEEN(db, VICTIM, attackerEEN, BALANCE(VICTIM))
              => SubBalance(VICTIM, amount)  and a stake whose Source = VICTIM
```

The victim performs **no delegatecall** and does not run attacker code in its own context. It only has to call out to an address the attacker controls — the same thing it does for every user payout.

---

## 2. Executed evidence

`go test -vet=off ./ledger/vm/ -run TestAuditH -v`

| PoC | Victim | Result |
|---|---|---|
| **H1** — claim pays `msg.sender` 1,000 wei, reward deducted first | payout contract, 250,000 TFuel | victim balance **0**; attacker contract holds the 1,000 wei; stake **249,999.999999999999999 TFuel**, `Source = victim`, in the attacker's EEN. Gas for the whole attack: **51,412** |
| **H2** — same victim shape, 1,370,000 TFuel | payout contract (NodeManager order of magnitude) | victim balance **0** in **one transaction**: 490,000 + 490,000 + 389,999.999999999999999 TFuel across three attacker-registered EENs; `GetTotalEENStake` inflated accordingly. The 500,000 per-EEN cap is bypassed by chunking |
| **H3** — zero-value notification hook (`CALL(gas, CALLER, 0, …)`) | notifier, 120,000 TFuel | victim balance **0**; stake **120,000 TFuel** sourced from the notifier |

---

## 3. The four questions, answered

1. **Does `0xCE` really debit TFuel from `CallerAddress`?** Yes — `contracts.go:104` reads `contract.CallerAddress` and passes it as `sender` to `StakeToEEN`, which checks `GetBalance(sender)` (`vm.go:203`) and executes `SubBalance(sender, amount)` (`vm.go:216`). The frame identity is what `AsDelegate` propagates (`contract.go:125`). Proven end-to-end in H1/H2/H3, not just by reading.

2. **Is the reward deducted before the callback?** Irrelevant. The attacker's bytecode computes the amount with the `BALANCE` opcode inside the callback, so it takes whatever is left at that instant — including transfers the victim has not yet made. H1 deliberately pays out the reward *before* the callback and still drains the remainder.

3. **Does it need a value-bearing `call{value}`?** No. A zero-value outgoing call creates the frame with the victim as `CallerAddress` all the same (H3). This widens the victim class from "payout contracts" to "any contract that pings an address supplied by a user or by an external party".

4. **Is 1.37M TFuel drainable given the 500k cap?** Yes, in one transaction, across *N* pre-registered EENs (H2). Cost to the attacker: 10,000 TFuel per EEN, which stays his own stake. **Caveat:** each individual deposit must be ≥ 10,000 TFuel, so a victim holding less than 10,000 TFuel cannot be drained this way, and the last chunk is whatever is left.

---

## 4. The sTFuel NodeManager instance: what is *not* verified

I could not verify the on-chain facts from this environment: the sandbox has no chain RPC access (only `github.com`, `codeload.github.com`, `api.github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`), and this repository contains no Solidity sources, no `NodeManager`, and no `sTFuel` reference (grep over `*.go|*.sol|*.md|*.json` returns nothing). **Therefore the ~1.37M TFuel balance, the public `claim`, and the `msg.sender.call{value}` shape remain unverified here.**

Three checks decide it, in this order:

1. **`eth_getBalance(0xd099…, "latest")`** — is there real native TFuel in the contract (not only internal accounting)?
2. **The gas forwarded to `msg.sender`.** This is the decisive one:
   * `payable(msg.sender).transfer(x)` / `.send(x)` forward **2,300 gas**. The attack needs **≈51,000 gas** (H1) and `0xCE` alone charges **21,000** (`protocol_params.go:102`). **With `transfer`/`send` the attack is impossible.**
   * `msg.sender.call{value: x}("")` forwards (almost) all gas → exploitable.
   * In bytecode: look for `GAS` (`0x5a`) immediately before `CALL` (`0xf1`) — or a large `PUSH2 0xffff`/`PUSH3 0xffffff` before it. A `PUSH2 0x08fc` (= 2300) before `CALL` means `transfer`, not exploitable.
3. **Reentrancy guard / checks-effects-interactions** around the payout: if the contract zeroes the claimable amount *and* blocks re-entry, the callback never runs. Note the guard has to be a real mutex — a "zero the balance first" pattern does not help, because the attacked asset is the contract's native TFuel balance, not its internal ledger.

If (1) and (2) hold, the NodeManager class of contracts is a **direct, one-transaction, whole-balance target**, and the 1.37M figure is drained in three chunks (H2).

---

## 5. Precise impact statement

* **Confirmed:** the victim contract's **entire liquid TFuel balance goes to 0** in one transaction, and every future TFuel inflow to that contract can be swept again on its next outbound call.
* **Confirmed:** the funds land in `Stake{Source: victim, Holder: attackerEEN}` — they are **not** transferred to the attacker's account.
* **Therefore:** the principal is **confiscated and permanently immobilized**, not stolen into the attacker's wallet. The victim contract cannot sign a transaction, and `UnstakeFromEEN` requires `CallerAddress == Source`, so only an outgoing call *originated by the victim itself* can unstake it. A payout contract has no such function, so the ~1.37M TFuel of user backing stays locked indefinitely: sTFuel becomes unbacked and redemptions stop.
* **The attacker's direct take:** the yield. The rewards of the stake accrue to the victim's *balance* (which he can sweep on the next callback) and, with the reward rule of #26 installed on his EEN, **10 % of that yield is paid to him permanently**.
* **Rollback caveat:** the drain lives inside the victim's snapshot (`EVM.Call` takes one at `vm.go:400`), so if the victim's own function reverts after the callback the whole drain is undone (PoC E). A normal `claim()` completes, so this does not protect the victim.

This is strictly stronger than the #25 wording ("griefing / yield"), and it is what makes a 1.37M TFuel contract a critical target — but it is a **confiscation**, not a transfer of principal to the attacker. I would not describe it as "the attacker ends up with 1.37M TFuel"; that would be wrong and easy to refute.

---

## 6. Mitigation

1. **Fix the root cause:** the staking precompiles must take the payer from `contract.Address()` (the executing account), never from `contract.CallerAddress`, and `AsDelegate` should not leave `CallerAddress` as the only identity the precompiles can see. Same bug class as #23/#24/#25; this report shows the cheapest victim trigger.
2. **Reject precompile calls in delegated frames** (`if contract.CallerAddress != contract.Address() && isPrecompile(addr) { return ErrInvalidStakeOperation }`), or pass an explicit `self` to `RunPrecompiledContract`.
3. **Re-check ownership at deposit time even for existing holders:** `vm.go:207` skips the BLS proof whenever the EEN exists, which is what allows an arbitrary third party's funds to be staked into somebody else's EEN.
4. **Use the 2,300-gas stipend (`transfer`) or a reentrancy mutex** for payouts in high-value contracts — defence in depth, not a fix.
