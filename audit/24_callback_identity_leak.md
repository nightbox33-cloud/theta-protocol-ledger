# #24 — «Callback identity leak»: cualquier tercero drena el THETA de cualquier contrato

**Auditoría:** Theta Protocol Ledger (EVM / precompiles de Theta)
**Commit auditado:** `f60ce0c87b92672986ba5dc7e22d3a61066feae6` (`master`, incluye el hardening `f670523`)
**Fecha:** 2026-11-07
**Rol:** exploit developer (PoC ejecutados contra código de producción, sin modificarlo)
**Naturaleza:** hallazgo **nuevo** — no es #23, ni #23b, ni #23c, ni #23d. Ver §2.

---

## 1. TL;DR

Los precompiles que mueven valor (**`0xCB transferTheta`**, y también **`0xCC`/`0xCE`** de staking) debitan
la cuenta `contract.CallerAddress` de la **frame actual**. En una frame creada por `DELEGATECALL`,
`CallerAddress` **no es la cuenta dueña de la frame**: es la dirección externa que llamó a la frame padre
(`Contract.AsDelegate()`, `ledger/vm/contract.go:121-130`).

Consecuencia: **si un contrato V hace cualquier llamada saliente a una dirección que su llamador puede
influir, ese llamador obtiene, dentro de la frame de retorno, la identidad `CallerAddress = V`, y puede
ejecutar `DELEGATECALL 0xCB` para vaciar el THETA de V.**

Lo que hace a #24 más grave que lo ya reportado:

| | #23 / #23b / #23c / #23d (ya reportado) | **#24 (este hallazgo)** |
|---|---|---|
| Quién inicia | La **víctima** (EOA o contrato) debe firmar/enviar una tx señuelo | **Cualquier tercero**, con una tx normal desde una EOA cualquiera |
| Cooperación de la víctima | Debe ejecutar código del atacante | Solo debe **llamar hacia fuera** (patrón normal: token, hook, callback, target, factory) |
| Alcance | 1 víctima por tx | **N víctimas por tx** (medido: 6; límite ≈ 834 con 20 M de gas) |
| Frame requerida | `CALL` | `CALL`, `STATICCALL` (bypass EIP-214) **y `CREATE` de init-code suministrado por el atacante** |
| Coste marginal | — | **23 956 gas ≈ 0,0958 TFuel por contrato drenado** |

Y la identidad filtrada **no se limita a THETA**: alcanza a `0xCC`/`0xCE`, con lo que un tercero puede
**forzar el staking del THETA/TFuel de un contrato ajeno en su propio Guardian/EEN** (bloqueo de fondos
por `ReturnLockingPeriod = 28 800` bloques y captura de hasta el 10 % del reward del stake ajeno). §9.

Estado de la evidencia: **8/8 PoCs PASS** contra `ledger/vm` de producción, sin tocar una línea del código
auditado (`git diff` del paquete = solo archivos `*_test.go` nuevos).

---

## 2. Por qué esto es un hallazgo distinto (y no una repetición)

Los hallazgos previos atacan el mismo *primitivo* (`DELEGATECALL 0xCB` hereda identidad) pero **siempre
desde una frame que la víctima ya está ejecutando**:

* **#23** — `DELEGATECALL 0xCB` hereda `CallerAddress`; demo: la víctima ejecuta el runtime de 23 bytes `60346000600037600060006034600060cb620f4240f400`.
* **#23b** — elevación `CALL` → contrato B → `DELEGATECALL`.
* **#23c** — autodrenaje con `thetaValue = 1 wei`.
* **#23d** — drenaje durante `STATICCALL`.

En los cuatro, el atacante necesita que **la víctima ejecute su código** (tx señuelo firmada por la víctima).
#24 aporta la pieza que faltaba y que cambia el modelo de amenaza: **el atacante no necesita que la víctima
ejecute nada suyo; le basta con que la víctima *llame* a una dirección influible y que el atacante esté
al otro lado.** La identidad de V se entrega *gratis* en la frame de callback, y la prueba es que el PoC C
drena **6 contratos distintos en una sola transacción** lanzada por una EOA sin relación con ellos.

Nota adicional no trivial: la frame de callback es **re-entrante y anidada**, así que el drenaje ocurre
*antes* de que V pueda comprobar nada: no hay `nonReentrant` que valga, porque el atacante nunca vuelve a
entrar en V (§5.2, B2) o no entra nunca (§5.4, D1/D2).

---

## 3. Causa raíz (código exacto)

### 3.1 Los precompiles confían en `CallerAddress`

`ledger/vm/contracts.go:455-466`:

```go
func (c *transferTheta) Run(evm *EVM, input []byte, callerAddr common.Address, contract *Contract) ([]byte, error) {
	recipient := common.BytesToAddress(getData(input, 0, 20))
	thetaWeiAmount := new(big.Int).SetBytes(getData(input, 20, 32))
	if !CanTransferTheta(evm.StateDB, callerAddr, thetaWeiAmount) {
		return common.Bytes{}, ErrInsufficientThetaBlance
	}
	// send Theta from the contract to the specified recipient
	TransferTheta(evm.StateDB, callerAddr, recipient, thetaWeiAmount)   // <-- debita callerAddr
	return common.Bytes{}, nil
}
```

`callerAddr` viene de la frame, no del input:

`ledger/vm/vm.go:257-264`

```go
func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := getPrecompiledContracts(blockHeight)
		if p := precompiles[*contract.CodeAddr]; p != nil {
			return RunPrecompiledContract(evm, p, input, contract)   // readOnly se ignora
		}
	}
```

y `RunPrecompiledContract` invoca `p.Run(evm, input, contract.CallerAddress, contract)`.

### 3.2 `DELEGATECALL` reescribe `CallerAddress` con el llamador de la frame **padre**

`ledger/vm/contract.go:66-67` y `121-130`:

```go
func NewContract(caller ContractRef, object ContractRef, ...) *Contract {
	c := &Contract{CallerAddress: caller.Address(), caller: caller, self: object}
	...
}

func (c *Contract) AsDelegate() *Contract {
	parent := c.caller.(*Contract)
	c.CallerAddress = parent.CallerAddress   // se salta un nivel: identidad EXTERNA
	c.value = parent.value
	c.thetaValue = parent.thetaValue
	return c
}
```

`ledger/vm/vm.go:496-519` (`DelegateCall`) construye `to = AccountRef(caller.Address())` y `.AsDelegate()`.

Es decir, en la frame `DELEGATECALL`:

* `contract.Address()` = la cuenta que ejecuta el código (el **self** del llamador),
* `contract.CallerAddress` = **quien llamó al llamador** (identidad externa),
* y el precompile usa **la segunda**.

En una tx directa `V → DELEGATECALL 0xCB` ambas coinciden con V y todo "funciona". En **cualquier frame
re-entrante** `CallerAddress` es la dirección que llamó a V ⇒ el atacante.

### 3.3 El vector: re-entrada o init-code

El atacante no necesita escribir en el storage de V ni cambiar su código. Solo dos formas de frame:

1. **V llama hacia fuera** a una dirección influible (calldata, `msg.sender`, lista de tokens, hook, target
   de un router) ⇒ el atacante está ahí y hace `DELEGATECALL 0xCB` (§5.1–§5.3).
2. **V despliega código que le pasa el llamador** (`CREATE` sobre `msg.data`) ⇒ el init-code del atacante
   corre en una frame con `CallerAddress = V` y hace `DELEGATECALL 0xCB` (§5.4).

---

## 4. Modelo de amenaza

```
Atacante EOA ──tx──> C (contrato del atacante)
                      C ──CALL────────────────────────────> V   frame: CallerAddress = C
                                                               V ──CALL/STATICCALL──> C   frame: CallerAddress = V
                      C'  (re-entrada)                            C' ──DELEGATECALL 0xCB (recipient=atacante, amount=balance(V))
                                                                  ⇒ TransferTheta(V → atacante)
```

Precondiciones (todas del lado de la víctima, ninguna del atacante):

* V **mantiene THETA** en su balance (wrapped THETA, colateral, depósitos, fees retenidas, etc.).
* V hace al menos una llamada saliente a una dirección que el llamador influye, **o** despliega bytecode que
  le pasa el llamador.
* Esa llamada **reenvía gas suficiente** (≥ ~25 000; un `transfer()`-style con estipendio de 2 300 gas es
  inmune, porque `ThetaTransferGas = 21 000`, `ledger/vm/params/protocol_params.go:100`).

No se requiere: firma de V, cooperación de V, acceso al storage de V, que V tenga funciones públicas
"peligrosas", ni que V confíe en el atacante de ninguna forma.

---

## 5. PoCs ejecutados (evidencia)

Harness: `ledger/vm/audit_common_test.go` (balance/código/tx sobre un `state.StoreView` real, altura
`19 000 000`, `SmartContractTx` → `vm.Execute`, es decir el mismo camino que producción).
Comando: `go test ./ledger/vm/ -run 'TestAudit' -v`.

### 5.1 B1 — víctima que llama a un target leído de calldata (`audit_b_callback_test.go`)

Víctima (runtime de 23 bytes): copia `calldata[0:32]` a memoria y hace `CALL(gas, target, 0,0,0,0,0)`.
Atacante: `CALL V` con `target = C`.
Drenaje: `drainerRuntime(attacker)` = `CALLER*2^96` → `STATICCALL 0xC9` (balance de V) → `DELEGATECALL 0xCB`
(recipient = atacante, amount = balance completo).

```
--- PASS: TestAuditB1_ThirdPartyDrainsContract_CallbackTarget
    victim contract theta : 0
    attacker EOA theta    : 100000000000000000000     (100 THETA)
```

### 5.2 B2 — víctima que llama a `msg.sender` (patrón callback/dispatcher)

Víctima: `CALL(gas, CALLER, 0,0,0,0,0)`. El atacante usa un **dispatcher** (`helperCtr`) que distingue
`CALLER == atacanteEOA` (fase de entrada → llama a V) de `CALLER == V` (re-entrada → drena). No hay
re-entrada en V en ningún momento ⇒ los `nonReentrant` de V son irrelevantes.

```
--- PASS: TestAuditB2_ThirdPartyDrainsContract_CallbackToSender
    victim contract theta : 0
    attacker EOA theta    : 250000000000000000000     (250 THETA)
```

### 5.3 B3 — víctima que **solo** hace una sonda `STATICCALL`

Víctima: `STATICCALL(gas, CALLER, ...)` (p. ej. `supportsInterface`, `balanceOf`, oracle probe).
`run(..., readOnly=true)` **no se propaga a los precompiles** (`vm.go:257-264`), así que el drenaje ocurre
dentro de una frame estática ⇒ bypass de EIP-214 sin escribir storage.

```
--- PASS: TestAuditB3_ThirdPartyDrainsContract_StaticProbe
    victim contract theta : 0
    attacker EOA theta    : 500000000000000000000     (500 THETA)
```

### 5.4 D1/D2 — frame **descendente**: `CREATE` de init-code suministrado por el atacante (`audit_d_create_test.go`)

Fábrica (`factoryRuntime = 366000600037 3660006000f000`): `CALLDATACOPY(msg.data)` + `CREATE(0, 0, size)`.
El init-code = el drainer del atacante. En la frame de init, `CallerAddress = V` ⇒ `DELEGATECALL 0xCB`
debita V. D2 hace lo mismo llamando a la fábrica **a través de un contrato router** del atacante (el
`tx.Origin` nunca toca la fábrica).

```
--- PASS: TestAuditD1_CreateInitCodeInheritsIdentity
    factory (victim) theta : 0
    attacker EOA theta     : 100000000000000000000
--- PASS: TestAuditD2_CreateViaContractCaller
    factory (victim) theta : 0
    attacker EOA theta     : 100000000000000000000
```

**Consecuencia de D1/D2:** cualquier contrato que despliegue bytecode suministrado por el llamador
(factories, deployers, proxy-factories, "multicall-deploy", ERC-4337-style factories) es drenable **sin ni
siquiera hacer una llamada saliente a un tercero**.

### 5.5 C — amplificación: **una sola tx drena N contratos** (`audit_c_sweep_test.go`)

`sweepContract(entry, victims, credit)`: si `CALLER == entry` salta al `LOOP` (que hace `CALL` a cada
víctima); el *fallthrough* es el drainer. Cada víctima llama de vuelta a `msg.sender` (patrón B2), y el
mismo contrato del atacante drena la identidad de **cada** víctima.

```
--- PASS: TestAuditC_OneTxDrainsManyContracts
    victim[0..5] theta = 0
    attacker gained in ONE transaction: 6000000000000000000000 thetaWei (6000 THETA)
```

### 5.6 C2 — economía real del sweep

```
gasUsed(n=2)=68934  gasUsed(n=10)=260582
  -> marginal gas per drained contract = 23956
  -> contracts drainable in one 20,000,000-gas tx ~= 834
  -> cost per drained contract = 95824000000000000 TFuelWei  (0.0958 TFuel @ 4e12 wei/gas)
```

* **23 956 gas/prototolo** (21 000 de `ThetaTransferGas` + ~2 956 de overhead: `DELEGATECALL` 700,
  `STATICCALL` 4 + overhead de memoria/`CALL`).
* **≈ 834 contratos por tx** con `MaximumTxGasLimitJune2021 = 20e6` (`ledger/types/const.go:34`).
* **Rentabilidad:** cada víctima solo tiene que tener THETA por valor > **0,0958 TFuel** para que el ataque
  sea rentable. Es decir: *cualquier* contrato con saldo relevante.
* El atacante puede además paralelizar en tantas tx como quiera (el sweep no consume estado global).

---

## 6. Superficie realista (qué contratos caen)

| Patrón en V | Forma | PoC |
|---|---|---|
| Router/agregador que llama a un `target`/`token` recibido por parámetro (`aggregate`, `swap`, `multicall` con target arbitrario) | B1 | ✔ |
| Contratos con hooks/callbacks al llamador (ERC-777-style, `onTokenTransfer`, "notify", flash-loan callbacks, `CALL msg.sender`) | B2 | ✔ |
| Contratos que solo **consultan** al llamador (`supportsInterface`, `balanceOf`, oráculos, ERC-165 probes) | B3 | ✔ |
| Factories/deployers que despliegan bytecode del llamador | D1/D2 | ✔ |
| Cualquier contrato que haga `delegatecall` a una librería cuyo address venga de calldata | B (§3.2) | ✔ (mismo mecanismo) |

Contratos **inmunes** (para que el informe sea honesto): los que nunca llaman hacia fuera; los que solo
llaman a direcciones constantes/inmutables no influibles; los que reenvían ≤ ~25 000 gas; los que no
mantienen THETA (el THETA dentro de una EEN/guardian stake no está en `Balance`, ver §9).

---

## 7. Por qué el impacto es "más letal" en la práctica

1. **Cero cooperación de la víctima.** No hay tx señuelo, no hay phishing, no hay firma. Basta con mirar la
   cadena, detectar contratos con THETA y código que llama hacia fuera, y disparar.
2. **Cualquiera puede ser el atacante** (no hace falta ser el dueño ni el llamador legítimo de V).
3. **Batch:** 834 contratos/tx, 0,0958 TFuel por contrato. El coste total de drenar 100 contratos es
   ≈ 9,6 TFuel.
4. **No se puede mitigar con `nonReentrant`** (B2 no re-entra en V; D1/D2 nunca entra).
5. **Funciona a través de `STATICCALL`** (B3), así que ni las rutas "read-only" están a salvo.
6. **Es silencioso:** la tx del atacante es una llamada normal a *su propio* contrato; el `from` no es la
   víctima, así que los monitores que filtran por "el dueño está siendo drenado" no ven nada raro.

---

## 8. (Descartado) H6 — la fuga de `refund` **no es explotable**

La hipótesis abierta ("`snapshotCheckpoint` no guarda `refund` ⇒ `AddRefund` sobrevive al revert ⇒
subfacturación") **no tiene efecto económico** en este fork:

* Los refunds **nunca se aplican** al fee: `ledger/execution/tx_smart_contract.go:174` calcula
  `feeAmount = GasPrice * gasUsed` con el `gasUsed` bruto devuelto por `vm.Execute`
  (`vm/exec.go:94`: `gasUsed = gasLimit - leftOverGas`), y `GetRefund()` **no se consulta en ningún
  punto fuera de `ledger/vm`** (`grep -rn GetRefund --include=*.go ledger/ | grep -v _test` ⇒ solo
  `storeview.go`).
* Por tanto el bug de snapshot es **código muerto** a efectos de fees. Se cierra la hipótesis.

Otras hipótesis verificadas y cerradas en esta ronda:

* **Maleabilidad de tx:** `SignBytes` = RLP de la estructura completa (`TxToBytes` → `rlp.EncodeToBytes`),
  no hay campos ejecutados fuera de la firma; los `big.Int` negativos ni siquiera sobreviven al RLP.
* **Panic por cuenta inexistente en los stake returns** (`ledger.go:704-707`, `:733-734`): las cuentas no se
  borran nunca del trie (`StoreView.Suicide` solo pone `CodeHash = SuicidedCodeHash` y transfiere TFuel), y
  cualquier `Source` de un stake tuvo que tener saldo ⇒ `GetAccount(source) != nil` siempre.
* **Robo de principal de staking:** todos los `handle*StakeReturn` acreditan `stake.Source`, que se fija en el
  depósito con la misma variable que se debita ⇒ no hay desalineación explotable.

---

## 9. Impacto secundario (mismo root cause): precompiles de staking

`0xCC stakeToGuardian` y `0xCE stakeToEEN` también usan `contract.CallerAddress` como titular
(`ledger/vm/vm.go:120-215`), y **`StakeToEEN` no hace ninguna comprobación BLS si la EEN ya existe**
(`vm.go:207`). Con la identidad filtrada de §3:

* Un tercero puede **forzar el staking del THETA de un contrato ajeno en su propio Guardian**
  (`MinGuardianStakeDeposit = 1 000 THETA` post-fork, `core/guardian.go:165-168`), repetible por cada
  Guardian/EEN propio.
* Un tercero puede **forzar el staking del TFuel de un contrato ajeno** en su EEN
  (`MinEliteEdgeNodeStakeDeposit = 10 000 TFuel`, `Max… = 500 000 TFuel`, `core/elite_edge_node.go:257-260`).
* Efecto: los fondos salen del `Balance` de la víctima (rompe cualquier contrato que cuente con su saldo),
  quedan **bloqueados `ReturnLockingPeriod = 28 800` bloques** tras el unstake (`core/stake.go:16`) y la
  víctima **no consiente** nada de esto.
* Rentabilidad para el atacante: por defecto el reward va al `Source` (`handleSplit`,
  `ledger/execution/tx_coinbase.go:470-473`), pero el atacante puede **pre-fijar una regla de split sobre su
  propio holder** (`StakeRewardDistributionTx`, cap 10 % en `tx_stake_reward_distribution.go:59-60`) y
  capturar hasta el **10 % del reward del stake de la víctima** mientras esté staked.
* `0xCD`/`0xCF` (unstake) permiten además **des-stakear el stake de la víctima** sin su consentimiento
  (inicia el retorno a la propia víctima; es griefing, no robo).

Estado: **verificado por lectura de código, sin PoC** (limitado por `Min*StakeDeposit`: requiere que la
víctima mantenga ≥ 1 000 THETA o ≥ 10 000 TFuel, y el beneficio directo está capado al 10 % del reward).
Se documenta como impacto colateral del mismo defecto, no como hallazgo independiente.

---

## 10. Mitigaciones

**Fix quirúrgico (recomendado).** El precompile no debe derivar la cuenta de `CallerAddress` en frames de
delegación. Opciones, de menor a mayor cambio:

1. **Rechazar los precompiles de valor en frames de delegación.** Marcar `Contract` con `isDelegate`
   (ya existe `AsDelegate()`), propagarlo a `RunPrecompiledContract`, y que `transferTheta`, `stakeToGuardian`
   y `stakeToEEN` devuelvan error si `isDelegate == true`. Rompe el vector entero con ~10 líneas y sin
   cambiar la semántica legítima (`V → CALL 0xCB` sigue funcionando; `V → DELEGATECALL 0xCB` deja de ser un
   traspaso de V).
2. **Derivar la cuenta del `self` de la frame del llamador**: pasar a `p.Run(...)` la dirección
   `contract.caller.(*Contract).Address()` en lugar de `contract.CallerAddress`. En una frame `CALL` da V;
   en una `DELEGATECALL` da la cuenta que ejecuta el código (el atacante) ⇒ sin robo. Requiere mantener el
   caso `depth == 0` (tx directa del EOA a `0xCB`) usando `tx.From`.
3. **Defensa en profundidad:** (a) propagar `readOnly` a los precompiles para que `STATICCALL` no pueda
   mutar estado (cierra §5.3 y todo #23d); (b) prohibir `delegatecall` a direcciones de precompile en
   `opDelegateCall`; (c) que `0xCB` exija `thetaWeiAmount > 0` y `recipient != callerAddr` (no arregla el
   fondo, pero elimina el autodrenaje trivial).

**Detección/monitoreo.** Alertar de txs cuyo `from` es un contrato/EOA sin relación con contratos que
pierden todo su `ThetaWei` en la misma tx, y de txs con > 10 `TransferTheta` desde el mismo frame.

**Nota de despliegue.** El fix es un cambio de consenso: requiere hard fork. Mientras tanto, los operadores
de contratos con THETA pueden paliarlo evitando llamadas salientes a direcciones influibles y desplegando
bytecode de terceros.

---

## 11. Cómo reproducir

```bash
# toolchain de este sandbox: go 1.27.3 en /usr/local/bin/go; deps resueltas por replaces locales
cd /home/user/theta-protocol-ledger
export GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
go build ./ledger/vm/                     # OK
go test ./ledger/vm/ -run 'TestAudit' -v  # 8/8 PASS
```

Archivos (todos nuevos, solo tests; el código auditado no se modifica):

| Archivo | Contenido |
|---|---|
| `ledger/vm/audit_common_test.go` | harness: `newAuditView`, `setBalance`, `setCode`, `runTx` (`vm.Execute` real), `drainerRuntime` |
| `ledger/vm/audit_a_sanity_test.go` | sanity: reproduce el drenaje conocido (#23) para validar el harness |
| `ledger/vm/audit_b_callback_test.go` | **B1** (target de calldata), **B2** (callback a `msg.sender` con dispatcher), **B3** (sonda `STATICCALL`) |
| `ledger/vm/audit_c_sweep_test.go` | **C** (N víctimas en 1 tx) y **C2** (gas marginal / presupuesto de 20 M) |
| `ledger/vm/audit_d_create_test.go` | **D1/D2** (init-code de `CREATE` hereda la identidad de la fábrica) |

Salida cruda de la última ejecución: `/tmp/audit_out.txt` (no persistente; reproducible con el comando de
arriba).

---

## 12. Resumen de severidad

| Aspecto | Valor |
|---|---|
| Confidencialidad/integridad de fondos | **Pérdida total del THETA** de los contratos afectados |
| Requisitos de atacante | Una EOA con TFuel para gas; ningún privilegio |
| Requisitos de víctima | Mantener THETA + hacer una llamada saliente influible (o desplegar bytecode del llamador) |
| Coste | 0,0958 TFuel por contrato; 1 tx para cientos de contratos |
| Detección por la víctima | Nula (la tx no la envía ella; su contrato solo "llamó a un token") |
| Mitigación en caliente | Ninguna (requiere hard fork) |

**Severidad propuesta: crítica.** Es explotable por cualquier tercero, sin cooperación, en lote, barato y
contra el patrón de contrato más común del ecosistema (llamar a una dirección influible).
