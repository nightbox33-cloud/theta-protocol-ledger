# Crítico: `TNT20TokenBank.unlockTokens` — quórum con un solo voto y sin cap de cantidad

Auditoría de los contratos de subchain (`theta-metachain-guide/sdk/contracts`,
fuentes consolidadas en `/home/user/theta-ecosystem/subchain-src/`).

Contratos auditados: `TokenBank`, `TFuelTokenBank`, `TNT20TokenBank`,
`TNT721TokenBank`, `TNT1155TokenBank`, `TNT20/721/1155VoucherContract`,
`VoucherMap`, `TokenBankUtils`, `ChainRegistrarOnMainchain`,
`ValidatorCollateralManager`, `ValidatorStakeManager`, `WithdrawalQueue`,
`SubchainGovernanceToken`.

---

## 1. El primitivo

`TNT20TokenBank.unlockTokens()` mueve tokens reales desde el balance del propio
bank:

```solidity
try ITNT20(targetChainTNT20Contract).transfer(targetChainTokenReceiver, unlockAmount)
```

donde `targetChainTNT20Contract` y `unlockAmount` salen **del `denom` que elige
el llamante** y del importe que se vota. Tres defectos se combinan:

1. **`sourceChainID` no está ligado al `denom`.**
   `unlockTokens(uint256 sourceChainID, string denom, ...)` canonicaliza el
   `denom`, extrae de él `targetChainTNT20Contract`, pero **nunca comprueba que
   `sourceChainID` coincida con el chainID embebido en el denom**. El digest que
   se vota incluye `sourceChainID`, así que el llamante lo elige libremente.

2. **El digest es forjable por quien controla el quórum.**
   `voucherBurnDataDigest = keccak256(abi.encodePacked(sourceChainID, denom,
   unlockAmount, receiver, dynasty, burnNonce))`. Todos esos campos los fija el
   proponente; el `burnNonce` sólo tiene que ser `maxProcessed+1`, que es
   predecible. No se exige ninguna prueba de que el burn haya ocurrido.

3. **No hay cap.** En `TFuelTokenBank.unlockTokens` existe
   `require(unlockAmount <= totalLockedAmounts[sourceChainID])`. En el banco
   TNT-20 ese check está **comentado**, junto con el registro de
   `totalLockedAmounts` (nota del comentario sobre tokens de supply elástica):

```solidity
// require(
//     unlockAmount <=
//         totalLockedAmounts[sourceChainID][targetChainTNT20Contract],
//     "Cannot unlock the requested amount of tokens"
// );
```

**Consecuencia:** con quórum se puede vaciar, al 100 %, cualquier TNT-20 que el
bank custodie, a cualquier dirección, sin haber quemado nada.

## 2. El quórum se consigue con UN solo voto

`TokenBank._checkValidatorQuorum`:

```solidity
if (vd.accumlatedShares.mul(3) >= totalShares.mul(2)) { ... return true; }
```

`totalShares` es la suma de los shares del validator set de esa subchain, y
`getValidatorSet` se deriva de `getStakeSnapshot(subchainID, prevDynastyEndingHeight)`.
En una subchain donde **el atacante es el primer y único staker**, el snapshot
contiene exactamente un validador con todos los shares ⇒
`1 share votado × 3 >= 1 share total × 2` ⇒ **quórum aprobado con su propio voto**.
No hace falta colusión con terceros.

**Corrección importante (descartado por mí mismo):** el caso `totalShares == 0`
**no** es explotable. Con el validator set vacío, el bucle no encuentra al
`msg.sender`, `isMsgSenderAValidator` queda en `false` y revierte en
`require(isMsgSenderAValidator, "Not a validator")`. El vector válido es "soy el
único validador", no "no hay validadores".

## 3. Coste real (números del propio contrato, no estimados)

| Requisito | Fuente | Importe |
|---|---|---|
| `registerSubchain` | `minChainCollateralAmount = 10000 ether` | **10.000 wTHETA** |
| `depositStake` → `vcm.minValidatorCollateralAmount` | `= 1000 ether` | **1.000 wTHETA** |
| `depositStake` `msg.value` | `initialFeeRequired` | ~1 TFUEL |
| delegación de shares | → propio nodo, coste 0 | — |
| **Capital total a inmovilizar** | | **≈ 11.000 wTHETA** |

Para dimensionar: al bloque actual wTHETA vale lo mismo que THETA. Con THETA a
0,1433 $, **≈ 1.580 $ de capital comprometido**.

### Recuperación (esto es lo que abarata el ataque)

- `deregisterSubchain` devuelve `subchainCollateralReturnPercentage = 95` ⇒ se
  pierden **500 wTHETA** (≈ 72 $).
- El colateral de validador se recupera: `withdrawStake` → esperar una dinastía
  (para salir del validator set, por el `require(!isAValidator)` de
  `withdrawCollateral`) → `withdrawCollateral` → `claimCollateral` tras
  `withdrawalPendingPeriodInBlocks`.

**Coste neto hundido ≈ 500 wTHETA.** El resto es colateral recuperable, no gasto.

### Y no hay atajo: ambas rutas exigen subchain registrada

`ChainRegistrarOnMainchain.depositCollateral()` y `.depositStake()` abren con
`require(this.isARegisteredSubchain(subchainID))`. No existe camino para ser
validador de una subchain sin que esa subchain esté registrada. Es decir: **no
hay versión barata que evite los 10.000 wTHETA.**

## 4. Por qué hoy no es un robo en curso

El botín es el saldo del `TNT20TokenBank` en mainnet
(`0xB3d93735de018Ad48122bf7394734A7d18007e1b`). Ese banco sólo tiene **41
movimientos TNT-20** en toda su historia, con lockeos individuales de 100–1.000
unidades de tokens menores. Los depósitos grandes que sí existen (TDROP, 95 % del
supply) están en `TDropStaking`, **no** en un token bank, y no son alcanzables por
esta vía.

Es decir: el capital a inmovilizar (11.000 THETA) excede con holgura lo que hoy
guarda el banco. **El primitivo es crítico; la instancia en mainnet todavía no
tiene valor suficiente para pagarlo.** Pasa a ser un robo rentable en cuanto un
bank de subchain custodie un token con liquidez — y `registerSubchain` es
permissionless, así que esa condición puede aparecer sin que nadie lo impida.

## 5. Fallos menores del mismo conjunto

- `ChainRegistrarOnMainchain.withdrawCollateral` pasa `block.number` en el
  parámetro que `getValidatorShares` interpreta como **dinastía**, no altura
  (confusión de unidades) ⇒ el check de "no retirar colateral mientras validas"
  compara contra la dinastía equivocada.
- `_splitFeeAmongSubchainValidators` paga dos veces al último validador (una en
  el bucle, otra con `remainingFee` si no es contrato) ⇒ sobrepago del fee.
- `deregisterSubchain` no limpia `subchainMetadataMap` ni `collateralAmount` ⇒
  el subchainID queda irrecuperable (griefing autofinanciado, ya documentado en
  el informe anterior).

## 6. Recomendación

1. `require(sourceChainID == TokenBankUtils.extractChainIDFromDenom(canonicalDenom))`.
2. Restaurar el cap `totalLockedAmounts[sourceChainID][token]`.
3. Rechazar `unlockAmount == 0` y exigir que el `denom` corresponda a un token
   efectivamente lockeado por este bank.
4. Como defensa en profundidad: exigir un mínimo de shares/votantes distintos
   (p. ej. `require(vd.signers.length >= 2)`) para que ninguna subchain con un
   único staker pueda aprobar transfers salientes.

---

# Ronda 2 — búsqueda de un vector sin phishing (resultado: negativo, con lo verificado)

Objetivo de esta ronda: encontrar robo **sin interacción de la víctima**. Todo lo
siguiente se leyó en código y se descartó con el motivo concreto.

## Lo nuevo que sí aparece

**`TNT721TokenBank.unlockTokens` es el gemelo exacto del fallo de TNT-20.**
También tiene el cap comentado:

```solidity
// require(
//     totalLockedAmounts[sourceChainID][targetChainTNT721Contract][tokenID] == 1,
//     "Cannot unlock the requested tokenID"
// );
```

Mismo patrón (denom del llamante, `sourceChainID` no ligado, digest forjable, cap
comentado). Es una **instancia nueva del mismo primitivo**, no un vector nuevo:
mismo coste de 10.000 wTHETA y misma barrera de quórum. `TNT1155TokenBank`
sigue el mismo esquema.

## Descartado con evidencia en esta ronda

| Hipótesis | Veredicto | Prueba |
|---|---|---|
| **Doble conteo de votos en consenso** — `HasMajorityVotes` suma stake por cada entrada de la lista y no deduplica; `AddVote` usa clave `ID:Block:Epoch`, así que un validador puede tener N entradas | **Cerrado** | `consensus/state.go:219-228`: `AddEpochVote` aplica `UniqueVoter()` al ingerir, así que el set persistido tiene como máximo un voto por ID. En `engine.go:1154` y `CommitCertificate.IsValid` se aplica además `UniqueVoter()`. Los sitios sin deduplicar (1048, 1371) leen ese set ya deduplicado. |
| `SplitRule` secuestrado por `resourceID` ajeno, `Duration` sin tope | Real pero **descartado por el usuario**: apagado en mainnet | — |
| `WithdrawStake` roba stake ajeno | No | `WithdrawStake(source, holder)` → `StakeHolder.withdrawStake` sólo casa `stake.Source == source` |
| Inputs negativos en `ServicePaymentTx` vacían el reserved fund | No | `TxInput.ValidateBasic` → `Coins.IsValid()` → `IsNonnegative()` |
| Firma nula en el `Target` de un service payment | No | `crypto.Signature.Verify`: `if sig == nil \|\| sig.IsEmpty() { return false }` |
| `sanityCheck` sin verificar firma del `SlashedAddress` | Real, pero **requires ser validador** y hoy `reserved_funds` está vacío en los 15 mayores holders |
| `bigModExp` (0x05) con `modLen`/`baseLen` enormes → pánico u OOM | No | `RequiredGas` cuadrático en `max(modLen, baseLen)`; si excede, `MaxUint64Val` → OOG |
| Reconstrucción de `bytecode` de `wTHETA` adulterada por el explorer | No | `code` on-chain = keccak(runtime) = `0x1b202d37…`, y la fuente verificada es coherente con la ABI y con los precompiles 0xC9/0xCB |
| `TDropStaking` con inflación de primera posición | No | `totalShares ≫ 0` en vivo; redondeo a favor del pool |

## Por qué no hay vector sin interacción en el core

El core no tiene una superficie donde un tercero mueva fondos de otra cuenta sin
una firma de esa cuenta o sin ser validador. Todos los caminos de movimiento de
saldo (`tx_send`, `tx_withdraw_stake`, `tx_release_fund`, `tx_service_payment`,
`tx_slash`) exigen o bien la firma del dueño del saldo, o bien privilegio de
validador. El único punto donde el ledger toca saldo de terceros sin esa firma es
el `CoinbaseTx`, y está atado al proposer del bloque.

**Prueba negativa explícita**: no encontré, en el core, ninguna ruta en la que
`sourceAccount` de una transacción sea distinta de la cuenta cuya firma se
verifica. `validateInputAdvanced` siempre verifica `in.Signature` contra
`acc.Address` de esa misma entrada.

## Nota de alcance

No probé payloads de inyección contra la API del explorer de producción: leer sus
endpoints GET públicos es usar la API, pero enviarle explotación sería test no
autorizado contra un servicio de terceros. Si se quiere cubrir ese frente, hay
que hacerlo sobre una instancia local del backend (`explorer-api`, Node.js +
Mongo), que sí es auditable sin tocar producción.
