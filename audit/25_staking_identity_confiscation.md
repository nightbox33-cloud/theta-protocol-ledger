# #25 — Confiscación de TFuel y de THETA *staked* de terceros (precompiles 0xCC/0xCD/0xCE/0xCF)

**Commit auditado:** `f60ce0c8` (`master`). **PoCs ejecutados:** `ledger/vm/audit_f_staking_test.go` (F1–F4, PASS).
**Relación con lo ya reportado:** es el mismo *root cause* de #23 (`DELEGATECALL` → `contract.CallerAddress` heredado), pero por primera vez alcanza **activos y precompiles que #23/#23b/#23c/#23d/#24 nunca tocaron**: **TFuel** (el token de gas, que no tiene ningún otro precompile que lo mueva) y **THETA en stake**. Y es monetizable: **secuestra el peso de recompensa de un EEN ajeno**.

---

## 1. Qué es nuevo (y por qué no es #23 otra vez)

| | #23 / #23b / #23c / #23d | **#25** |
|---|---|---|
| Precompile | `0xCB transferTheta` | **`0xCC stakeToGuardian`, `0xCD unstakeFromGuardian`, `0xCE stakeToEEN`, `0xCF unstakeFromEEN`** |
| Activo | THETA **libre** (`Balance`) | **TFuel libre** (¡el token de gas!) **y THETA libre convertido en stake** |
| Efecto | transferencia al atacante | **el saldo de la víctima → 0**, los fondos quedan en un stake **cuyo holder es el atacante**, bloqueados `ReturnLockingPeriod = 28 800` bloques, y con **peso de recompensa** para el atacante |
| Recuperación por la víctima | ninguna (pérdida definitiva) | ninguna sin pasar por el lock; el atacante puede **volver a confiscar** en la misma tx siguiente |
| Vector de entrada | la víctima firma una tx señuelo | **sin firma ni cooperación**: basta con que un contrato haga una llamada saliente (mismo requisito que el callback leak) |
| Profit del atacante | 100 % del THETA | **hasta el 10 % del yield del stake ajeno de forma perpetua + multiplicación del peso de recompensa de su EEN** (§4) |

Dos detalles de código lo hacen trivial, y son los que ningún reporte previo señaló:

1. `ledger/vm/vm.go:143` — `if !gcp.Contains(guardianAddr) { if !checkBlsSummary(...) { return false } }`
   `ledger/vm/vm.go:207` — `if een == nil && !checkBlsSummary(...) { return false }`
   ⇒ **si el guardian/EEN ya existe, no se verifica NINGUNA prueba de propiedad**. El atacante registra su propio guardian/EEN una vez (1 000 THETA / 10 000 TFuel, capital recuperable) y desde entonces puede depositar fondos **de cualquier tercero** en él.
2. `ledger/vm/vm.go:120-215` — el titular que se debita es `contract.CallerAddress`; tras un `DELEGATECALL` ese campo es **la identidad externa** (`contract.go:121-130`, `AsDelegate`), es decir, la víctima. `StakeToEEN` sólo exige `db.GetBalance(sender) >= amount` (vm.go:190) sobre esa identidad suplantada.

Combinado: **el frame del atacante puede retirar el 100 % del TFuel (o THETA) de la víctima y depositarlo en un nodo del atacante, sin que la víctima firme nada.**

---

## 2. Evidencia ejecutada

`go test ./ledger/vm/ -run 'TestAuditF' -v` → **4/4 PASS** contra `ledger/vm` de producción sin modificarlo.

### F1 — TFuel confiscado (vía `0xCE`)

Víctima: contrato con **250 000 TFuel** y código `CALL(gas, msg.sender, …)` (callback normal).
Atacante: contrato dispatcher que, al ser re-entrado (`CALLER == víctima`), hace `DELEGATECALL 0xCE`
con el *summary* de su propio EEN y `amount = 250 000 TFuel`.

```
err                          = <nil>
victim contract TFuel        = 0
victim stake in attacker EEN = 250000000000000000000000   (holder=0xee00…01)
total EEN stake              = 260000000000000000000000
```

### F2 — THETA confiscado y convertido en stake (vía `0xCC`)

Igual, pero `DELEGATECALL 0xCC` y la víctima tiene **5 000 THETA**:

```
victim contract Theta             = 0
victim stake in attacker guardian = 5000000000000000000000  (holder=0xaa00…01)
```

### F3 — Congelación: el atacante también puede forzar el *unstake* (`0xCD`)

```
victim stake withdrawn = true, returnHeight = 19028800
 (current height 19000000, ReturnLockingPeriod = 28800)
```

Es decir: con la misma identidad suplantada el atacante **decide cuándo** empieza el lock de 2 días del stake de la víctima (y mientras esté `Withdrawn`, la víctima **no puede volver a depositar**: `core/stake.go:137-141`).

### F4 — Amplificación: **1 tx confisca el TFuel de N contratos**

```
5 contracts had their ENTIRE TFuel balance moved into one attacker EEN
EEN total stake now = 110000 TFuel
  stake source=0x2222… (atacante)   amount=10 000 TFuel
  stake source=0xc00000             amount=20 000 TFuel
  stake source=0xc00001             amount=20 000 TFuel
  … (x5)
gasUsed for 5 victims in one tx = 137 517  (~27 503 gas per confiscated contract)
```

**27 503 gas ≈ 0,11 TFuel por contrato confiscado** (a 4e12 wei/gas), sin necesidad de la sonda `0xC9` (el importe va en el input, calculado off-chain: los balances son públicos). Con 20 M de gas por tx: **≈ 727 contratos por transacción**.

---

## 3. Precondiciones y límites (honestos)

* El contrato víctima debe hacer **una** llamada saliente a una dirección influible por su llamador (mismo requisito que #24/#23d: callback, hook, target de calldata, sonda).
* Límites de depósito por nodo: guardian ≥ **1 000 THETA** (`core/guardian.go:165-168`), EEN entre **10 000** y **500 000 TFuel** (`core/elite_edge_node.go:257-260`). Un contrato con más fondos requiere varios nodos del atacante (cada uno es capital recuperable).
* El **principal** del stake sigue perteneciendo a la víctima (`Source`), y le es devuelto a los `ReturnLockingPeriod` bloques del unstake. **No hay robo del principal** — lo verifiqué y lo dejo explícito para no sobre-vender.

---

## 4. Por qué sigue siendo rentable para el atacante (el *drain* real es de yield, no de principal)

Las recompensas de EEN se reparten por **peso de stake** (`state/elite_edge_node_pool.go:37-90`: muestreo tipo Algorand proporcional a `stake/TotalEENStake`) y luego se dividen por `handleSplit` (`ledger/execution/tx_coinbase.go:460-495`):

* el peso de un EEN es proporcional a su stake total ⇒ **al inyectar el stake de la víctima, el nodo del atacante multiplica su peso** (F1: de 10 000 a 260 000 TFuel = **×26**; el techo es 500 000 por nodo, ×N nodos) y **se lleva esa fracción del pool de recompensas a costa de los demás EEN** (dilución);
* el *split rule* lo fija el **holder** con `StakeRewardDistributionTx` (firmada por él, `tx_stake_reward_distribution.go:132-150`), con tope del **10 %** (`:59-60`) ⇒ el atacante se queda **10 % del yield del dinero de la víctima, para siempre**, sin arriesgar capital propio;
* la víctima, mientras tanto, **pierde el uso de sus fondos** (gas token bloqueado ≥ 28 800 bloques = ~2 días por ciclo, y el atacante puede repetirlo indefinidamente), y **cualquier contrato que lea su propio saldo (`0xC9`) queda insolvente a voluntad**.

Coste del ataque: **0,11 TFuel por contrato** (F4). Capital requerido: el del nodo (recuperable: basta con hacer unstake, esperar el lock y recuperarlo).

---

## 5. Reproducir

```bash
cd /home/user/theta-protocol-ledger
export GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
go test ./ledger/vm/ -run 'TestAuditF' -v     # F1..F4 PASS
go test ./ledger/vm/ -run 'TestAuditE' -v     # controles negativos (ver §6)
```

Runtimes construidos en el test (`precompileDelegatePayload`, `dispatcher`, `sweepStakeContract`); el payload de 293 B se escribe con `PUSH32`/`MSTORE` (10 palabras) y se pasa con `DELEGATECALL(gas, 0xCE, 0, 320, 0, 0)`.
El summary BLS es sintácticamente válido (pubkey/pop reales de `bls.RandKey()`) pero **no se verifica** porque el nodo del atacante ya existe (vm.go:207).

---

## 6. Controles negativos ejecutados (para acotar el alcance)

| Hipótesis | Resultado |
|---|---|
| Una transferencia de valor sobrevive a un `REVERT` de su frame | **NO** — `TestAuditE1`: la víctima conserva 100 THETA. El snapshot del `StoreView` revierte el árbol correctamente |
| Una transferencia de valor sobrevive a un `INVALID`/excepción | **NO** — `TestAuditE2` |
| `Fungible` negativo (mint) por `Coins` en RLP | **NO** — RLP serializa el valor absoluto y `TxInput/TxOutput.ValidateBasic → Coins.IsValid() = IsNonnegative()` lo rechaza |
| Aliasing de `*big.Int` en `Coins.Plus/Minus` (H5) | **NO** — `Plus`/`Minus`/`Negative` asignan `new(big.Int)`; no mutan los operandos |
| `refund` sobrevive al revert ⇒ subfacturación (H6) | **NO** — los refunds **nunca se aplican** al fee (`tx_smart_contract.go:174` usa el `gasUsed` bruto; `GetRefund()` no se usa fuera de `vm`) ⇒ código muerto |
| `SubRefund` underflow ⇒ panic/chain halt | **NO** — `GetCommittedState()` devuelve `GetState()` (`storeview.go:677-679`), así que `original == current` siempre y la rama con `SubRefund` es inalcanzable. (Efecto colateral real: el metering EIP-1283 está roto ⇒ los SSTOREs "sucios" cuestan 5 000 en vez de 200; sobrecobra, no regala) |
| Precompiles con importe negativo (`SetBytes` es sin signo) | **NO** |
| El `holder` BLS de un guardian/EEN existente se puede reemplazar | **NO** — `core/guardian.go:311-330` ignora `blsPubkey` cuando el guardian ya existe |

---

## 7. Mitigación

Misma que #24 (el defecto es de la capa EVM, no de los precompiles):

1. **`TransferTheta`, `StakeToGuardian`, `StakeToEEN` deben rechazarse en frames de delegación** (marcar `Contract.isDelegate` en `AsDelegate()` y propagarlo a `RunPrecompiledContract`), o
2. derivar la cuenta de `contract.caller.(*Contract).Address()` en lugar de `CallerAddress`, o
3. prohibir `delegatecall` a direcciones de precompile en `opDelegateCall`.
4. Defensa en profundidad: exigir la prueba BLS **siempre** (no sólo cuando el nodo no existe), y propagar `readOnly` a los precompiles.
5. Mientras no haya hard fork: los contratos con TFuel/THETA no deben llamar a direcciones influibles por el llamador.

**Severidad propuesta: alta (crítica en cuanto a disponibilidad y a extracción de yield).** No hay robo del principal (la víctima lo recupera tras el lock), pero sí: (a) confiscación del 100 % del TFuel de un contrato en una tx de 0,11 TFuel, (b) congelación repetible en el tiempo, (c) secuestro del peso de recompensa (×26 medido) y 10 % del yield ajeno de forma perpetua, (d) batch (≈727 contratos/tx).
