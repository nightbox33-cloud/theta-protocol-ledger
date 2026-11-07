# #28 — The sTFuel NodeManager instance: source confirmed, `nonReentrant` irrelevant, 100 % of the TVL reachable

**Component:** `0xCE` (`stakeToEEN`) + `0xCF` (`unstakeFromEEN`) precompiles, reached from a payout callback
**Source of the instance:** `github.com/sTFuel/sTFuel` @ commit `26bd340` (2026-02-17), `packages/smart-contracts/`
— `nodeManager.sol` (1,546 lines), `sTFuel.sol` (545), `AdminMultisig.sol`, plus the project's own `Smart_TFuel_Audit.pdf`
**PoC:** `ledger/vm/audit_h_callback_payout_test.go` — `TestAuditH1…H5` (all green)
**Status:** mechanism **CONFIRMED by execution**; the instance is **CONFIRMED at source level**;
the *deployed* bytecode at `0xd099…` is still **not** verified from this session (§7).

---

## 0. Verdict

| Question from #27 §4 | Answer |
|---|---|
| Does the NodeManager hold *real native* TFuel, or only internal accounting? | **Native value.** Every payout pays `address(this).balance` through `_pay` → `payable(to).call{value:…}`, and its own staking goes through the native precompile `address(0xce).call(data)` (`nodeManager.sol:1526`). The on-chain *amount* is still unverified (§7). |
| `call{value}` (all gas) or `transfer`/`send` (2,300 gas)? | **`call{value}` with all remaining gas** — `nodeManager.sol:891-894`. There is no `.transfer(` / `.send(` anywhere in the payout path. ⇒ **exploitable** |
| Is there a genuine reentrancy mutex? | **Yes — and it does not matter.** `nonReentrant` on `:546`, `:589`, `:606`. It blocks re-entry *into the NodeManager*; the attack never re-enters it (H4). |
| Is the drain limited to the liquid balance? | **No.** The same callback also calls `0xCF`, which queues **the NodeManager's entire EEN stake** for return (`nodeManager.sol` has no control over the frame's `CallerAddress`). H5, and `1` on the return queue with `Source = NodeManager`. |

**One-line impact:** an ordinary sTFuel user (a contract with a fallback) drains the NodeManager's liquid TFuel to zero and pushes 100 % of its staked TFuel into the return queue in a **single transaction**; a second identical callback after `ReturnLockingPeriod` sweeps the returned principal, so the backing of every sTFuel share goes to ≈ 0.

---

## 1. Provenance of the source

```
repo     https://github.com/sTFuel/sTFuel
commit   26bd340299397d5bd9d6acc871eea0970c68986f   (2026-02-17)
files    packages/smart-contracts/nodeManager.sol    1546 lines
         packages/smart-contracts/sTFuel.sol          545 lines
         packages/smart-contracts/AdminMultisig.sol   229 lines
         packages/smart-contracts/Smart_TFuel_Audit.pdf
```

Two independent checks tie this source to the deployed system:

1. **The payout shape matches the recon note exactly** — `_pay(address to, uint256 amount)` is implemented as
   `payable(to).call{value: amount}("")` (`nodeManager.sol:891-894`), i.e. the "pago al `msg.sender` con `call{value}`" the hypothesis described.
2. **The EEN summary is 261 bytes** (`nodeManager.sol:139`, `:368`, `:1521-1524`), and the contract builds the precompile
   input as `abi.encodePacked(eenSummary /*261*/, amount /*32*/)` → a **293-byte** payload with the amount at offset **261**.
   That is *exactly* the layout decoded in `ledger/vm/contracts.go:519-521` (`summary = getData(input, 0, 229)`,
   `amount = getData(input, 261, 32)`) and *exactly* the payload built by the PoC (`delegateStakeToEEN`, inSize `293`, amount written at `261`).
   The contract's own encoding and the node's decoder agree; the PoC is therefore faithful, not an approximation.

**Caveat, stated up front:** the repository contains **no deployed address** (every address constant in
`packages/*/src/contracts/contracts.ts` is `0x000…0`), and this session has no chain RPC. So the mapping
"`0xd099…` ⇒ this exact source" rests on the two checks above, not on a bytecode comparison. §7 lists the one-minute check that closes it.

---

## 2. The call chain, with the real contract's lines

```
EOA  ──tx──►  attacker contract A
              sTFuel.burnAndRedeemDirect(amount)            sTFuel.sol:408
                 └─ nm.directRedeem(msg.sender, net)        sTFuel.sol:425      (msg.sender = A)
              or sTFuel.claimTFuelAsHeadOfQueue()           sTFuel.sol:465-468  → claimHeadIfReady(msg.sender)
              or sTFuel.claimTFuel()                        sTFuel.sol:476-479  → withdrawCredits(msg.sender)

NodeManager.directRedeem(user=A, amount)                    nodeManager.sol:589
   require(msg.sender == sTFuel)                            nodeManager.sol:259-262   onlySTFuel  ✔ (called by sTFuel)
   nonReentrant                                             nodeManager.sol:589        lock set
   require(address(this).balance >= amount + reserved)      nodeManager.sol:590        (about the amount paid, not the call)
   _pay(user, amount)                                       nodeManager.sol:592
      (bool ok, ) = payable(to).call{value: amount}("")     nodeManager.sol:891-894   ← ALL GAS, native value
      ↓   frame with CallerAddress = NodeManager
A.fallback()
   DELEGATECALL 0xCE  (input = <summary 261><amount 32>)     contracts.go:104  callerAddr := contract.CallerAddress
                                                             contracts.go:519  StakeToEEN(db, callerAddr, …)
                                                             contract.go:121-130  AsDelegate keeps parent's CallerAddress
                                                             vm.go:203/207/216    balance check, BLS skip, SubBalance
   DELEGATECALL 0xCF  (input = <eenAddr 20>)                 contracts.go:539-541 → vm.go:222-243 → core/stake.go:152-165
                                                             stake.Source == NodeManager  ⇒ withdrawn = true,
                                                             ReturnHeight = height + 28800
```

Nothing in the NodeManager runs between `_pay` and the attacker's code, and nothing in the NodeManager can observe
*which* address a nested precompile call in the attacker's frame resolves to: the precompiles read
`contract.CallerAddress` (`contracts.go:104`), which is a property of the frame, not of the NodeManager's storage.

---

## 3. Evidence (executed, `ledger/vm/audit_h_callback_payout_test.go`)

| Test | Setup | Result |
|---|---|---|
| **H1** | payout contract holds 250,000 TFuel, pays `msg.sender` 1,000 wei (reward deducted *before* the callback) | payer balance **0**, stake **249,999.999999999999999 TFuel** with `Source = payer`, attacker contract holds the 1,000 wei, **gas 51,412** |
| **H2** | payer 1,370,000 TFuel | **0 in one tx**: 490,000 + 490,000 + 389,999.999… across 3 attacker EENs — the 500k per-EEN cap is not a bound |
| **H3** | hook with **zero value** (`CALL(gas, CALLER, 0, …)`) | 120,000 TFuel drained — a real payout value is not even required |
| **H4** | **faithful `nonReentrant` model** of `nodeManager.sol:546/589/606` + `_pay`: lock slot set on entry, guarded revert on re-entry, cleared on exit | nested re-entry returns **0** (mutex held), NodeManager balance **0**, stake **249,999.999…** with `Source = NodeManager`, lock released (`slot0 == 0`) |
| **H5** | NodeManager holds 250,000 liquid **and** 200,000 staked in its own EEN; callback = `0xCE`(liquid) + `0xCF`(its EEN) | liquid **0**, attacker EEN stake 249,999.999…, NodeManager's own stake `withdrawn = true`, `returnHeight = 19028800`, **return queue = 1 entry** `{holder 0xEE…66, source 0xd099…05, amount 200,000 TFuel}` |

H4 is the answer to "but it has a reentrancy guard": **the mutex works and is irrelevant** — the attack uses the
precompile, not the contract.

---

## 4. Why the contract's own defences do not fire

| Defence | Line | Why it does not apply |
|---|---|---|
| `nonReentrant` on every payout entry point | `:546`, `:589`, `:606` | Only blocks calls *into* the NodeManager. H4: the mutex holds, the balance still leaves. |
| `require(balanceBefore - address(this).balance <= amount, "TFUEL_DRAIN_TOO_HIGH")` | `:1528` | Wraps **the contract's own** `0xCE` call (`:1526`). The attacker's `0xCE` call happens in the attacker's frame; the NodeManager's `balanceBefore` snapshot is never taken. |
| `require(balanceBefore == address(this).balance, "TFUEL_DRAINED")` | `:1544` | Same: wraps the contract's own `0xCF` call (`:1542`). It does not prevent the attacker's `0xCF` from queuing the same stakes (H5). |
| `_checkAndStakeTFuel()` right after `_pay` | `:569-574`, `:592-593`, body `:918-931` | `if (liquid < MIN_STAKE_AMOUNT) return;` (`:922`, `MIN_STAKE_AMOUNT = 10_000 ether` at `:41`). After the drain `liquid == 0` ⇒ early return ⇒ **no revert, no rollback of the drain**. |
| Balance pre-conditions before paying | `:554`, `:590`, `:611` | They constrain the *amount paid*, not what the recipient does with the frame. H1 pays 1,000 wei and still empties the contract. |
| Withdrawal cooldown / FIFO | `:519`, `COOLDOWN_PERIOD = 28_800` (`:44`) | Only relevant to the *queue* path. `burnAndRedeemDirect` (`sTFuel.sol:408`) is immediate, needs no cooldown. |

Note the irony: `:1528` is precisely the guard that would have killed this attack — it just is not applied to `_pay`.

---

## 5. Impact on sTFuel

The value of a share is derived from

```
getNetAssetsBackingShares() = address(this).balance + totalStakedTFuel + effectiveUnstaking - reserved
                              nodeManager.sol:830
```

After one transaction (H5):

* `address(this).balance` → **0** (drained into attacker EEN stakes, `Source = NodeManager`);
* `totalStakedTFuel` → **0** for the staked part (H5: the stakes are withdrawn, so the internal counter follows them into the return queue);
* `effectiveUnstaking` → only counted before `ReturnHeight`.

⇒ **backing per share ≈ 0**, for every holder, permanently. `sTFuel.sol:226/242` price shares from exactly this number.
Every holder's claim on the pool is destroyed; the attacker cannot be outbid or front-run, and there is no admin path
that recreates the principal (`AdminMultisig` can pause new staking, not mint TFuel).

**Attacker P&L, honestly stated (same correction as #27):** the resulting stakes carry `Source = NodeManager`
(`vm.go:203-216` takes the source from `CallerAddress`), and `UnstakeFromEEN`/`ReturnStake` require
`stake.Source == caller` (`core/stake.go:152-165`). So the principal stays *titled* to the NodeManager:
the attacker **confiscates and immobilises** the TVL, he does not own it. His direct gain is the staking yield
(and up to 10 % of it under the #26 rule), plus the ability to keep the funds cycling forever.

**Two callbacks, not one:**

1. callback #1 — drain the liquid balance (`0xCE`) **and** queue all of the NodeManager's EEN stakes (`0xCF`);
2. after `ReturnLockingPeriod` (28,800 blocks ≈ 2 days at Theta's block time), `ledger/ledger.go:741-742` credits
   `returnedStake.Source` (= the NodeManager) with the principal;
3. callback #2 — identical to H1/H3, sweeps the live balance (`BALANCE` opcode, no hardcoded amount).

Gas cost: 51,412 for the drain (H1) + 21,000 per `0xCF` call (`params.StakeToGuardianGas`, shared by `0xCE`/`0xCF`).

**Practical requirement for the attacker:** be a contract (a fallback is what receives the frame) and hold a
minimal amount of sTFuel — e.g. deposit via `sTFuel.sol:325` (`nodeManager.depositTFuel{value: msg.value}()`),
then call `burnAndRedeemDirect` (`sTFuel.sol:408`) with a small amount. The payout he receives is irrelevant (H1: 1,000 wei;
H3: zero).

---

## 6. Cost envelope and what is *not* drainable

* Anything below `MIN_STAKE_AMOUNT = 10,000 TFuel` (`:41`) cannot be moved out with `0xCE` in a single chunk
  (per-EEN deposit floor, `ledger/state/elite_edge_node_pool.go:216-223`), but it can be swept in the same transaction
  by a second chunk on another EEN, or simply left for callback #2.
* The 500,000 TFuel per-EEN cap is not a bound on the *theft*, only on the *chunk size* (H2: 1.37 M in one tx).

---

## 7. What remains unverified, and the exact checks that close it

This session has no Theta RPC (the sandbox reaches `github.com` only), so the following three facts about the **live**
`0xd099…` contract could not be measured here. Each check is a single call and is decisive:

1. **Source ↔ bytecode match.** Search the deployed runtime for a `PUSH2 0x08fc` (2,300) immediately before the `CALL`
   that pays the user. If the deployed version uses `.transfer`/`.send`, the attack is impossible on-chain and this
   report must be closed for that address. (Given `_pay` in source, expect `GAS` + `CALL` with no stipend constant.)
2. **Real native balance.** `eth_getBalance(0xd099…, "latest")` — confirms the ≈ 1.37 M TFuel figure and that it is
   native value, not an internal ledger (the source already shows it is native: `:891-894`, `:1526`).
3. **Size of the staked part.** `totalStakedTFuel()` and the node list — H5 shows the staked part is reachable too, so
   the TVL at risk is `balance + totalStakedTFuel`, not the balance alone.

Until (1) is done, the honest status of the *instance* is: **confirmed in source, unconfirmed on-chain**.

---

## 8. Mitigation

1. **Pull payments.** `_pay` should credit `pendingWithdrawals[to]` and let the user call a separate `withdraw()`
   in their own transaction. No callback, no attacker frame, no leak. This single change removes the whole class.
2. **Reject contracts as payout recipients** — `require(to.code.length == 0, "EOA_ONLY")` in `_pay`. A contract must hold
   code to receive the callback, so this is sufficient (and cheaper than (1) in review effort, at the cost of
   composability and of smart-contract treasuries).
3. **Extend the guard that already exists.** Wrap `_pay` in the same post-call check used at `:1528`:
   `uint256 before = address(this).balance; _pay(to, amount); require(before - address(this).balance <= amount);`
   Any drain during the callback then reverts the whole transaction.
4. **Belt and braces:** make `0xCE`/`0xCF` revert when `CallerAddress` is a contract that was entered through a
   value transfer (protocol-level, heavy), or simply document that no contract may call the staking precompiles from a
   callback — the last option is not enforceable, hence (1)–(3).

Fixing `_pay` in `nodeManager.sol:891-894` and redeploying/upgrading the NodeManager is the only complete remedy;
`sTFuel.sol`'s `nonReentrant` (`:408`, `:465`, `:476`) does not help, for the reason H4 demonstrates.
