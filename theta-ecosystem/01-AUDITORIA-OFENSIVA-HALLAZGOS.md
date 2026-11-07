# Auditoría ofensiva Theta — hallazgos y descartes (estado live)

Base de código: `theta-protocol-ledger` @ `f60ce0c8` (v4.1.4, master actual del repo oficial, 2026-09-17),
`theta-protocol-subchain`, `theta-metachain-guide` (fuente Solidity del despliegue mainnet),
`tdrop-governance`, `theta-wallet-web` (ABIs/`chainId` reales).

Herramientas: lectura de código + `gh api` (histórico de fixes) + HTML del explorador. **No hay RPC ni
`eth_getCode` accesible desde este entorno** (`/api/*` del explorador devuelve la home; `curl` sin egreso),
por lo que el bytecode live de contratos de subchain **no se pudo verificar**.

---

## 1. Veredicto

**No hay crítico de robo que pase los 4 criterios.** Ningún camino permissionless, desde el estado
desplegado, termina con el atacante retirando valor de terceros sin aportar capital ≥ lo obtenido.

Lo que sí existe: (a) un cluster de **fallos económicos** en el ledger (el "deterrente de colateral" del
sistema de micropagos está muerto) y (b) un **griefing permissionless** en el metachain (IDs de subchain
irrecuperables) que quema el 5 % del propio atacante. Ambos incumplen el criterio (4): el PnL del atacante
es ≤ 0 o el daño no es sustracción de fondos ajenos.

---

## 2. Inventario medido (bloque ≈ 36.610.600, THETA $0,1423, TFUEL $0,00756)

| Objeto | Dirección | Valor live |
|---|---|---|
| wTHETA (TNT‑20) | `0xaf537fb7e4c77c97403de94ce141b7edb9f7fcf0` | supply **914.195,34**, 2.063 holders, 203.351 transferencias |
| ChainRegistrarOnMainchain | `0xb164c26fd7970746639151a8C118cce282F272A7` | **60.500 wTHETA**, seq 2, ~20+ llamadas en 72 h |
| ValidatorCollateralManager (`vcm`, creado en constructor) | `0xf0d53cbe585f8fa24a5108a1c741ce31ad18b40e` | **25.000 wTHETA**, seq 0 |
| ValidatorStakeManager (`vsm`) | `0xf0716e6221618137fb05d72450e0fc8d9c2919d4` | **89.768.632,06 RPLAY**, seq 4, 0 wTHETA |
| TDropStaking | `0xa89c744Db76266ecA60e2b0F62Afcd1f8581b7ed` | **9.492.210.882,84 TDROP** (≈95 % del supply) |
| TDROP (contrato, reserva) | `0x1336739B05C7Ab8a526D40DCC0d04a826b5f8B03` | 2.733.418,79 TDROP, seq 0 |
| TFuelTokenBank (mainchain) | `0xf83239088B8766a27cD1f46772a2E1f88e916322` | 224.576,49 TFUEL (≈1.700 $) |
| TNT20TokenBank (mainchain) | `0xB3d93735de018Ad48122bf7394734A7d18007e1b` | 369.907 TDROP + 205 wTHETA + 1.999,9 Lavita |
| THETA en staking de nodos | `ls/vcp`, `ls/gcp` | ~31,8 % de 1 B THETA (≈318 M, ≈45 M $) |
| TFUEL staked (EEN) | `ls/eentas` | **0 %** (0 EEN activos) |

Lectura clave: el premio grande es **(a)** el pool de TDROP (9,49 B, pero sin liquidez de salida) y
**(b)** el staking nativo de THETA (318 M). El bridge/token banks del metachain custodian **<$40 k reales**
en wTHETA + 224 k TFUEL. Cualquier "crítico" que sólo toque los banks tiene techo de daño de 4 cifras.

---

## 3. Lo verificado: no existe acuñación ni doble crédito en el core ledger

Revisado exhaustivamente esta ronda:

* **Todo camino que escribe saldo positivo**: `executils.go:252` (`adjustByOutputs`), `tx_coinbase.go:132`,
  `tx_slash.go:129`, `ledger.go:683/712/742` (retornos de stake), `account.go:161/202/256`
  (release/transfer de reservas). No hay ninguno sin débito previo o sin límite de pool.
* **`SendTx`** (`tx_send.go:87-92`): `inTotal == outTotal + fee` ⇒ no hay salida sin entrada.
  A partir de `HeightEnableSmartContract` rechaza destinatarios con código (`tx_send.go:65-73`).
* **`Coins`** (`coin.go`): `Plus/Minus/CalculatePercentage` normalizan con `NoNil()` y todos los caminos
  verifican `IsValid()/IsNonnegative()`; los importes negativos serializados por RLP se rechazan antes de
  tocar estado (`txWithdraw…`, `txDeposit…`, `sanityCheckForFee`).
* **`Snapshot/RevertToSnapshot`** (`storeview.go:784-798`): las fotos son monótonas y se invalidan al
  resetear frame, por lo que un sub‑call que revierte no puede "ahorrar" un snapshot previo con menos logs.
  Los 12 vectores del hardening de 2026-04 (`f670523a`) están cubiertos; no quedó ninguno abierto.
* **Retorno de stake** (`core/stake.go:161-190`, `ledger.go:646-760`): el stake se **borra del pool antes de
  acreditar** ⇒ la función es idempotente; un doble crédito requeriría dos entradas en la lista del mismo
  `source`, lo que `depositStake` bloquea (`Cannot deposit during the withdrawal locking period`).
* **Sobrescritura de cuenta desde el VM**: `AddBalance/SubBalance` releen del trie, así que un
  `view.SetAccount(addr, acc)` posterior sólo puede pisar secuencia/saldos propios, no acreditar.
* **`SetSkipSanityCheck`** (`executor.go:77-79`) **no tiene ningún llamador** ⇒ coinbase y slash siempre
  validan firmas, proposer y montos calculados. El "mint de recompensas arbitrarias" está cerrado.
* **Precompiles de staking** `0xcc/0xce` (`vm.go:100-219`): `DepositStake(sender=caller, …)` y
  `CanTransfer/CanTransferTheta(sender)` ⇒ un contrato sólo puede stakear **su** saldo; `0xcd/0xcf`
  retiran sólo stakes cuyo `Source == caller`. (La familia `AsDelegate`/`CallerAddress` ya conocida
  #23‑#25 sigue siendo el único vector de identidad, y su variante de robo es #23 vía
  `SmartContractTx` con `thetaWei>0`.)
* **`0xb6 mintTFuel`** (subchain): `HasPreviledgedAccess(caller)` compara contra
  `GetTFuelTokenBankContractAddress()` leído del trie de génesis; ni EOA ni contrato de usuario puede
  producirlo (el `nil` deref si la clave no existe es sólo un panic de nodo, no un bypass).

---

## 4. Hallazgo nuevo (no es robo): `deregisterSubchain` deja el subchainID irrecuperable

`ChainRegistrarOnMainchain.deregisterSubchain` (fuente mainnet, `/tmp/sc-src/ChainRegistrarOnMainchain.sol`
líneas 1196‑1241):

```solidity
require(!vcm.hasValidatorCollaterals(subchainID), …);
require(subchainMetadata.exists, …);
require(msg.sender == chainGuarantor, …);
uint256 returnAoumnt = collateralAmount * subchainCollateralReturnPercentage / 100; // 95 %
IERC20(wTheta).transfer(chainGuarantor, returnAoumnt);
// NO se borra subchainMetadataMap ⇒ exists sigue true
// NO se resetea collateralAmount ⇒ sigue el valor viejo
```

Consecuencias reales (verificadas contra el código, no supuestas):

1. **`registerSubchain` revierte para siempre con ese ID** (`!subchainMetadata.exists`), porque la única
   rama que borra la entrada está comentada (nota del propio autor sobre replay).
2. **`addSubchainCollateral` se puede seguir llamando** sobre la entrada "fantasma" (sólo exige
   `exists` y `msg.sender == guarantor`), sin que exista subchain. Ese wTHETA queda en el contrato sin
   función de retorno (el `deregister` posterior pagaría `95 % × collateralAmount`, es decir, otra vez
   el principal antiguo).
3. Coste para el atacante: **5 % del colateral por cada ID** (~500 wTHETA ≈ 71 $ por ciclo de 10.000).
   Gana: nada. Daño: ese `chainID` queda permanentemente inutilizable por el dueño legítimo.

**Por qué no es crítico (criterio 4):** el pago vuelve al propio atacante, es autofinanciado con pérdida y
el impacto es DoS de un identificador, no sustracción de fondos ajenos. Lo reporto como **Medio**:
especificación rota (`exists` como bandera de "registrado" en vez de "registrable") con efecto
permanente, y a diferencia del resto de DoS este no caduca.

Vector hermano, mismo contrato, `withdrawCollateral` (líneas 1265‑1290): pasa **`block.number`** como 2.º
argumento de `vsm.getValidatorShares(subchainID, dynasty, validator)`; `getValidatorSet` lo interpreta como
*dynastia* y calcula `prevDynastyEndingHeight = numBlocksPerDynasty*dynasty - 1` (≈7,3·10¹¹), lo que hace
que `getStakeSnapshot` devuelva el **último** snapshot en vez del de la dinastía en curso. Como los
depósitos/retiros de stake sólo entran en vigor en la dinastía siguiente, un validador puede retirar el
colateral **mientras sigue validando**, y `slashCollateral` ya no tendría de dónde cortar. Efecto:
**evasión de slashing** (debilita la seguridad del subchain), no robo de terceros.

---

## 5. Cluster económico del core: el colateral de micropagos nunca se ejecuta

1. `ledger/execution/tx_service_payment.go:140-145` — el overspend detectado se descarta:
   ```go
   shouldSlash, _ := sourceAccount.TransferReservedFund(…)
   if shouldSlash {
       //view.AddSlashIntent(slashIntent)     ← comentado
   }
   ```
2. `ledger/types/account.go:230-265` — si el `ResourceID` no pertenece al `ReservedFund` o no hay
   `ReserveSequence`, `TransferReservedFund` hace `return false, SlashIntent{}` **sin transferir**, y el
   `process` sigue: el tx se cobra (fee) y "tiene éxito" moviendo 0.
3. `ledger/types/reserved_fund.go:73-88` — `VerifyPaymentSequence` indexa por **dirección destino**, no por
   `resourceID`; junto con (2) permite reabrir la secuencia por cada `ResourceID` del fund sin consumir
   saldo (sólo cobra el destinatario, no drena al pagador).
4. `CheckTransferReservedFund` usa `view.Height()` como "current" (`tx_service_payment.go:87`) mientras
   `process` usa `exec.state.Height()` (`tx_reserve_fund.go:105`, `tx_release_fund.go:66/90`): frontera de
   expiración desfasada 1 bloque respecto al chequeo.

Resultado agregado: el "pool de micropagos" anunciado en el whitepaper (colateral slasheable si el emisor
gasta de más) **no puede castigarse on‑chain**. Es una propiedad de seguridad rota, pero el único afectado
económico es el propio emisor que gasta de más contra peers (daño al receptor ≤ 0, no hay fondos de
terceros custodiados en `ReservedFunds`). No cumple el criterio (4).

---

## 6. TDropStaking (9,49 B TDROP): revisado, sin drenaje

`tdrop-governance/contracts/TDropStaking.sol`:

* `stake`: `prevBalance = poolTDropBalance()` se lee **antes** de `transferFrom` (línea 172‑181) ⇒ el precio
  de la share no se puede manipular con el propio depósito.
* `unstake`: `amount = poolTDropBalance() * shares / totalShares` con `updateReward()` previo y **floor** en
  ambas direcciones ⇒ el redondeo favorece al pool, no al que sale.
* `updateReward` mints a favor del pool y adelanta `lastRewardMintHeight`; si el tope `maxStakeReward`
  (4 B, ampliable a 8 B) se alcanza, el mint se omite silenciosamente ⇒ pérdida para stakers, nunca
  ganancia para un tercero.
* `_delegate`/`getPriorVotes` conservan el guard de Compound (`blockNumber < block.number`) ⇒ no hay
  flash‑stake de votos.
* Único defecto real: **inflación de primera posición** (donación + `totalShares==0` ⇒ `newShares==0` para
  la víctima, con `stake` sin exigir `newShares>0`). **No es live**: el pool ya tiene `totalShares ≫ 0`
  (9,49 B), y para reabrirlo habría que llevar `totalShares` a 0, lo que exige que salgan todos los
  stakers. Sólo habría sido explotable en el bloque de despliegue.

---

## 7. Descartado con motivo (para no volver a gastar esfuerzo)

| Candidato | Por qué no es crítico live |
|---|---|
| #29 `unlockTokens` sin tope (TNT20/721/1155) | Descartado por el cliente (known issue). |
| #23/#23c `0xCB` debita `CallerAddress` | Real, pero en mainnet sólo se alcanza con phishing de una `SmartContractTx` firmada con `thetaWei>0`; es ingeniería social, no permissionless. |
| #28 `sTFuel` → `0xCE/0xCF` vía fallback | Falta bytecode live de `0xd099…`; la única firma disponible (`spywolf`, `NodeManager.sol:891-894`) describe `call{value:}`, y **no** se pudo confirmar en cadena. Sin `eth_getCode` no se sostiene. |
| `SplitRuleTx` sin dueño del `resourceID` | Feature muerta (0 txs tipo 6; último split sep‑2023) y sólo TFuel; exposición ~0. |
| Coinbase/slash arbitrarios | `SetSkipSanityCheck` sin llamadores; `CalculateReward` valida monto y destinatarios. |
| Doble retorno de stake (VCP/GCP/EEN) | `returnStake` borra del pool antes de acreditar (idempotente por construcción). |
| `0xb6 mintTFuel` libre | Gate por dirección del token bank del génesis (no controlable por usuario). |
| Griefing de `deregisterSubchain` | Self‑funded (‑5 %), no sustrae a terceros → ver §4. |

---

## 8. Qué haría falta para cerrar el caso (limitaciones de este entorno)

1. **`eth_getCode` de `0xd0999f0f…`** (NodeManager sTFuel) y de los 4 TokenBanks de subchain: decide #28 y
   permite comprobar si el bytecode desplegado coincide con la fuente revisada. Sin RPC no hay forma.
2. **Estado de `wTokenBank`/`ChainRegistrarOnSubchain`** en cada subchain (Lavita/EEN/…) para medir el
   colateral por subchain y el TVL real del metachain.
3. **Bytecode de `0xaf537fb7…` (wTHETA)**: el ABI del wallet incluye `getThetaBalance`/`deposit`/`fallback`,
   pero la fuente del despliegue no está en los repos (sólo `MockWrappedTheta`). Es el único contrato con
   THETA nativo dentro; sin su bytecode no se puede auditar el `withdraw`.
