# 04 — Modelo corregido del bug `readOnly` y barrido de mainnet

> Este documento **corrige** el 03. El 03 partía de dos premisas falsas. Se conserva
> como registro histórico, pero **no debe citarse**: sus conclusiones de identidad
> y su inventario están superados por lo de aquí.

---

## 1. Dos correcciones al modelo anterior

### Error 1 — «hace falta `delegatecall`». Falso.

`NewContract` (`ledger/vm/contract.go:67`) fija siempre
`CallerAddress = caller.Address()`:

| Entrada del atacante | `CallerAddress` en el frame del precompilado |
|---|---|
| `CALL` a `0xCB`/`0xCE` | **el contrato víctima** (que es el `caller`) |
| **`STATICCALL`** a `0xCB`/`0xCE` | **el contrato víctima** |
| `DELEGATECALL` / `CALLCODE` | el contrato víctima |

En `run()` (`ledger/vm/vm.go:258-272`) el precompilado se resuelve por
`contract.CodeAddr` y se invoca con `RunPrecompiledContract(evm, p, input, contract)`,
que usa `contract.CallerAddress`. **`readOnly` no se propaga** (el intérprete lo
conserva en su propio campo, `interpreter.go:134`, pero el camino del precompilado
ni lo recibe).

⇒ **Cualquier** `call`, `staticcall`, `read` o smartcontracttx sirve. No se necesita
`delegatecall`; basta con que un contrato ejecute código dirigido a `0xCB`/`0xCE`.

### Error 2 — «un contrato con THETA que pague al llamante». Incompleto.

El precompilado **no** debita el saldo del «llamante del llamante»: debita el de
`CallerAddress` del frame, que es **el contrato que hace la llamada**. Si la víctima
te paga con `call{value}` desde su propio frame, el `self` sigue siendo la víctima,
no tú. El pago con `call{value}` **no es requisito**. El requisito real es:

> **que el contrato víctima ejecute una instrucción cuyo destino y cuyo `input`
> pueda controlar el atacante.**

Ese `input` es el que se interpreta como argumentos del precompilado.

---

## 2. La primitiva exacta, con el activo que mueve

`ledger/vm/contracts.go` (mapa `PrecompiledContractsWrappedThetaSupport`):

| Addr | Tipo | `callerAddr` se usa como | Activo debitado | ¿Destino elegible por el atacante? |
|---|---|---|---|---|
| `0xC9` | `thetaBalance` | — (sólo lectura) | — | — |
| `0xCA` | `thetaStake` | — (sólo lectura) | — | — |
| **`0xCB`** | `transferTheta` | **`sender`** | **THETA** (`SubThetaBalance`) | **Sí**: `input[0:20]` = destinatario |
| `0xCC` | `stakeToGuardian` | `sender` | THETA | No: requiere firma del holder |
| **`0xCE`** | `stakeToEEN` | `sender` | **TFUEL** (`db.SubBalance`) | No: requiere firma BLS propia |
| `0xCD`/`0xCF` | unstake | `source` | — (marca retirada) | No |

**`0xCE` es el único que mueve TFUEL nativo**, y `0xCB` el único que mueve THETA
nativo hacia una dirección del atacante.

### La cadena de `0xCB` (verificada en código)

```
0xCB.Run(evm, input, callerAddr = C, contract)
  recipient      = input[0:20]
  thetaWeiAmount = input[20:52]
  CanTransferTheta(evm.StateDB, C, amount)
  TransferTheta(evm.StateDB, C, recipient, amount)   // C = contrato víctima
```

⇒ El atacante elige **destinatario y cantidad**, y el pago sale del balance de la
víctima. **Es irreversible**: no hay stake, no hay `Source`, no hay devolución.

### La cadena de `0xCE` (verificada, y por qué NO es robo)

`StakeToEEN` (`ledger/vm/vm.go:175`) exige `db.GetBalance(sender) >= amount` y, al
crear el EEN, `checkBlsSummary(blsPubkey, blsPop, holderSig, eenAddr)`
(`vm.go:105-125`): POP de BLS válido **y** `holderSig.Verify(blsPop.ToBytes(), eenAddr)`.
El atacante puede fabricarse todo eso con su propia clave BLS y su propia dirección
`eenAddr` (es su material, no el de la víctima).

Pero el stake queda registrado como `Stake{Source: <víctima>}` dentro del holder
`eenAddr` (`elite_edge_node_pool.go:211+`), y para retirarlo:

- `withdrawStake` (`core/stake.go:152`) exige `stake.Source == source`, donde
  `source` **es siempre el firmante de la tx** (`UnstakeFromEEN(db, addr=callerAddr, …)`).
- `returnStake` (`core/stake.go:167`) devuelve el TFUEL **al `Source`**.

⇒ **Sólo la víctima puede retirar, y el dinero vuelve a la víctima.** `0xCE` es
*bloqueo* (28.800 bloques ≈ 1 día tras el unstake), **no transferencia**. Queda
descartado con este número: no es un crítico de robo.

---

## 3. Requisito exacto para explotar `0xCB` hoy

Las tres condiciones, simultáneas y comprobables:

1. El contrato debe tener **THETA nativo** (`thetawei > 0`).
2. Debe ejecutar una instrucción hacia una dirección **que el atacante elija**.
3. El `input` de esa instrucción debe ser **bytes crudos del atacante**
   (no un `abi.encodeWithSelector` fijo: los 4 bytes del selector rompen el
   alineamiento `input[0:20]` = destinatario).

La condición 3 es la que mata a casi todos los candidatos: cualquier contrato que
llame a `IERC20(token).transferFrom(...)` con `token` controlado por el usuario
**no** sirve, porque el calldata empieza por el selector de 4 bytes y el
destinatario quedaría como `selector ‖ from[:16]`, que el atacante no puede elegir.

Lo que se necesita es un **ejecutor genérico**: `target.call(data)` con `target` y
`data` ambos de entrada del usuario (patrón multicall / proxy-executor / agregador).

---

## 4. Barrido de mainnet: qué hay realmente

### 4.1 Las direcciones «de DeFi» del frontend del explorer eran falsas

El grep de la ronda anterior sobre `frontend/src/common/constants.js` extrajo
cadenas de 64 hex **truncadas** a 40: eran **topic hashes de eventos**
(`TFuelTokenLocked`, `TNT20VoucherMinted`, …). Rehecho exigiendo exactamente 40
hex, y añadiendo los repos de contratos, el inventario real es:

| Dirección | Qué es | THETA | TFUEL |
|---|---|---|---|
| `0xaf537fb7e4c77c97403de94ce141b7edb9f7fcf0` | **wTHETA** (verificado, fuente completa) | **914.195,336** | 0 |
| `0xd551fd014d98edf6362c0c4e141dd7331888d9f8` | pool de staking **no verificado** | 0 | **234.040.254** |
| `0x4dc08b15ea0e10b96c41aec22fab934ba15c983e` | **WTFuel** (verificado, `withdraw` usa `.transfer`) | 0 | 13.099.859 |
| `0x51900b0f79dc8141c02ead7647bc43e8e10406a3` | «sTFuel» del repo | 0 | 22 (**es EOA**: `code` = keccak del vacío) |
| `0xedcc06ab18b9bd5b88af451f1bf86f6cf375d0b9` | «NodeManager» del repo | — | **la cuenta no existe** (`error_not_found`) |

⇒ **La versión de sTFuel/NodeManager del repositorio no está desplegada en esas
direcciones.** El contrato de `0xd551…` **no es** el `nodeManager.sol` del repo:
sus strings de revert («zero locking period is not allowed», «invalid owner for the
withdrawal queue», «totalTFuelOwnedByThePool») **no existen** en el repositorio
(`grep -F` sobre todo el árbol: 0 coincidencias). No se puede citar ese fuente como
prueba de esa instancia.

### 4.2 Hot wallets y swaps: descartados con motivo

- **Hot wallets**: los 200 mayores tenedores de THETA son **EOA** (`code` = keccak
  del vacío). Una EOA no ejecuta bytecode: no puede llamar a `0xCB`. El puesto 200
  tiene **203.719,650 THETA**, que es el techo de todo lo robable por esta vía en
  ese conjunto. Binance `0xf977814e…` (109,1 M THETA) es EOA.
- **Swaps / pools**: los pools de Theta custodian **WTFUEL (TNT-20)**, no TFUEL
  nativo; los routers pagan con `TransferHelper.safeTransferETH` → `call{value}`
  al *beneficiario que el usuario declara*, con calldata vacía ⇒ `input[0:20]` = 0.
  No sirven para `0xCB` ni para `0xCE` (no hay 229 bytes que controlar).
- **WTFuel**: `withdraw()` usa `msg.sender.transfer(wad)` ⇒ 2.300 gas <
  `params.ThetaTransferGas = 21.000` (`protocol_params.go:100`). Aunque se llegase
  al frame, el precompilado se queda sin gas. Descartado con número.

### 4.3 El contrato más rico está limpio (y lo he leído entero)

wTHETA es el único contrato con THETA nativo relevante. Su fuente verificada:

```solidity
function withdraw(uint amount) external nonReentrant {
    require(balanceOf(msg.sender) >= amount, "Insufficient balance");
    require(amount > 0, "No theta amount to withdraw");
    prevBalance = getThetaBalance() - amount;
    _burn(msg.sender, amount);
    _transferTheta(msg.sender, amount);        // -> address(0xcb).call(data)
    emit Withdrawal(msg.sender, amount);
}
```

- `_transferTheta` hace `address(0xcb).call(data)` ⇒ `CallerAddress` = **wTHETA**,
  y `dst = msg.sender`. El importe sale de wTHETA, pero **después** de quemar tu
  wTHETA y con el `require(balanceOf >= amount)`. Es 1:1, no hay robo.
- `_deposit` acuña `currBalance - prevBalance`. Verifiqué el invariante al wei:
  `totalSupply` = saldo nativo = **914.195.336.035.309.817.063.571** ⇒ no hay
  donación huérfana que el primero en depositar pueda acuñar.
- `nonReentrant` cubre `withdraw`, `deposit` y el `fallback`.
- Los únicos destinos externos son `0xC9` y `0xCB`, con `input` **no** controlable
  por el atacante. **Falla la condición 3.**

---

## 5. Conclusión honesta

**No he podido demostrar hoy un robo de fondos con este vector.** Lo que sí queda
demostrado, en código y con números:

1. **El defecto es real y es de clase crítica**: `run()` ignora `readOnly`, así que
   `0xCB` **muta estado dentro de un `STATICCALL`**. Cualquier contrato que haga una
   *lectura* contra una dirección elegida por el usuario pasa a ser drenable.
2. **El daño máximo es el 100 % del THETA nativo del contrato víctima**, de forma
   irreversible, sin firma de la víctima (basta una llamada a una función pública
   de lectura/ejecución).
3. **No hay instancia viva en mainnet** entre los contratos con saldo nativo que he
   podido leer: wTHETA (914 k THETA), WTFuel, y los dos pools de TFUEL. Todos fallan
   la condición 3.
4. `0xCE` mueve TFUEL, pero **devuelve el dinero a la víctima** (`Source`): es
   bloqueo, no robo.

**El hueco que queda por barrer, y que sí cerraría el crítico**, es un *ejecutor
genérico* en mainnet: un contrato que exponga `execute(target, data)` / multicall
con `data` crudo **y** tenga THETA nativo. Enumerarlos requiere `eth_getCode` sobre
candidatos (el explorer no tiene endpoint de listado de contratos), lo cual en este
entorno no es posible: sólo hay `fetch_page` y la API `:8443` no expone esa ruta.

---

## 6. Recomendación al proyecto (una línea, cinco precompilados)

En `run()` (`ledger/vm/vm.go:258-272`), antes del despacho:

```go
if readOnly && precompiles[*contract.CodeAddr] != nil {
    if _, mutating := ...; mutating { return nil, ErrWriteProtection }
}
```

o, más simple y a prueba de futuro: **que `RunPrecompiledContract` reciba `readOnly`
y que todo precompilado que toque `StateDB` lo rechace**. Protege `0xCB`, `0xCC`,
`0xCD`, `0xCE` y `0xCF` de golpe, y restaura la garantía que el intérprete de
bytecode ya da para `SSTORE`/`LOG`/`CALL` con valor.
