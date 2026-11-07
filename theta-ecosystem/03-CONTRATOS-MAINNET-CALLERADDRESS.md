# Familia CallerAddress: inventario de contratos mainnet y por qué no hay instancia viva

Objetivo: encontrar un contrato mainnet con THETA nativo que llame a `0xCB`
(`transferTheta`) mediante **delegatecall**, de forma que `CallerAddress` herede la
identidad del contrato y se pueda drenar su saldo sin que la víctima firme nada.

Conclusión: **no existe esa instancia hoy**. Abajo el inventario completo y la
prueba de cada descarte.

---

## 1. El mecanismo, fijado en código

`run()` (`ledger/vm/vm.go:258-267`) despacha a precompilado e **ignora el flag
`readOnly`**: sólo pasa `(evm, p, input, contract)`. Consecuencia real:

> Cualquier precompilado que mute estado (0xCB `transferTheta`, 0xCC/0xCE stake,
> 0xCD/0xCF unstake) **ejecuta esa mutación dentro de un `STATICCALL`**, donde el
> intérprete de bytecode sí lo habría prohibido (`ErrExecutionReverted`).

Verificado por eliminación: 0xCB → `SubThetaBalance/AddThetaBalance`; 0xCC →
`StakeToGuardian` → `db.SubThetaBalance`; 0xCE → `StakeToEEN` → `db.SubBalance`;
0xCD → `UnstakeFromGuardian` → `WithdrawStake`; 0xCF → `UnstakeFromEEN` →
`WithdrawStake`. Los demás (0x01-0x08, 0xC9, 0xCA) son de sólo lectura.

Identidad: en un `CALL` normal `NewContract(caller,…)` fija
`CallerAddress = caller.Address()` = `msg.sender` real, así que la familia sólo se
materializa con **delegatecall** (`AsDelegate()` hereda `CallerAddress` del padre).

## 2. Inventario de contratos con fondo nativo en mainnet

Barrido de `account/top/{theta,tfuel}` (300 mayores cuentas) cruzando el campo
`code` contra el keccak del código vacío
(`0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`).

**Top 200 de THETA: cero contratos.** Los 200 mayores tenedores de THETA son EOA
—exchanges y hot wallets—. No hay ni un solo contrato con THETA nativo en ese
conjunto. wTHETA (`0xaf537fb7…`) queda fuera del top pero es el único contrato
con THETA (914.195,336), y ya se auditó: targets fijos 0xC9/0xCB, sin delegatecall.

**Top 100 de TFUEL: dos contratos.**

| Contrato | TFUEL | THETA | Veredicto |
|---|---|---|---|
| `0xd551fd014d98edf6362c0c4e141dd7331888d9f8` | **234.040.254,54** | **0** | NodeManager de sTFuel. No verificable por ABI (devuelve `abi: ""`), dispatcher con ~90 selectores. **Cero THETA ⇒ 0xCB no tiene nada que mover.** Su activo es TFUEL, movido con precompilados 0xC9/0xCA (lectura) y `.transfer`/`call` en Solidity, no con la familia CallerAddress. |
| `0x4dc08b15ea0e10b96c41aec22fab934ba15c983e` | 13.099.859,80 | 0 | **`WTFuel`** (Wrapped TFuel), fuente verificada, solc 0.4.26, 2021-01-29. `withdraw` usa `msg.sender.transfer(wad)`. |

### Por qué `WTFuel` no es explotable

Dos barreras independientes:

1. `payable.transfer` reenvía **2.300 gas**. La llamada a `0xCB` cuesta
   `params.ThetaTransferGas = 21000` (`ledger/vm/params/protocol_params.go:100`).
   No cabe: el fallback del atacante revierte por OOG. La nota de #28 ("si
   `.transfer`, la instancia se cierra") queda **confirmada con el número
   concreto**: 2.300 < 21.000.
2. `WTFuel` no tiene delegatecall ni proxy: todo es `transferFrom` directo.

## 3. Estado del invariante de wTHETA (verificado al wei)

| Magnitud | Valor |
|---|---|
| `totalSupply` según explorer | `914195336035309817063571` |
| Saldo THETA nativo on-chain | `914195336035309817063571` |

**Cuadran exactamente.** No hay exceso de wTHETA sin respaldo, ni reserva huérfana
de THETA. El escenario "prevBalance global + sandwich" no deja residuo: cualquier
THETA extra por encima de `totalSupply` es reclamable por el siguiente
depositante (`_deposit` acredita `currBalance - prevBalance`), y en el instante
medido ese delta es cero. Así que **hoy no hay botín sin dueño** en wTHETA.

## 4. Requisito estructural que ningún candidato cumple

Para cerrar el círculo hace falta un contrato con **las tres** cosas:

1. saldo de **THETA** nativo (no TFUEL),
2. una ruta **`payable`/fallback** que envíe nativo a una dirección elegida por el
   llamante (para disparar su fallback),
3. un **delegatecall** a código del atacante (para que `CallerAddress` herede la
   identidad del contrato y `0xCB` debite de él).

Ni `WTFuel` (falla 3 y el gas), ni el NodeManager (falla 1: cero THETA), ni
wTHETA (falla 2: no acepta THETA por `_deposit` de forma arbitraria ni hace
delegatecall) cumplen las tres. En el top 200 de THETA no hay ningún contrato,
así que la superficie **no está poblada**: es una ausencia demostrada, no una
impresión.

## 5. Recomendación (independiente de la explotabilidad)

El defecto de fondo sigue siendo real y barato de arreglar:

1. **`run()` debe rechazar precompilados que mutan estado cuando `readOnly` es
   true.** Es una línea, protege los cinco precompilados a la vez y no depende de
   que hoy exista una instancia explotable.
2. `RunPrecompiledContract` debería usar el `msgSender` real
   (`evm.Context.Origin` como mínimo sano, o propagar el sender del frame) en vez
   de `contract.CallerAddress`, que `AsDelegate()` hereda del padre.
3. `transferTheta` (0xCB) nunca debería poder debitar del `self` del contrato
   víctima vía delegación: exigir que el débito coincida con el caller del frame
   exterior.

El punto 1 es el que más valor tiene: aunque el vector necesite phishing hoy, el
`readOnly` ignorado es una primitiva latente que se convierte en crítica en cuanto
alguien despliegue un contrato con las tres condiciones.
