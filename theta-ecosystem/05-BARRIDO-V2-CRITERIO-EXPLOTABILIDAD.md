# 05 — Barrido v2: inventario por direcciones documentadas y criterio de explotabilidad

> Corrige el método del 04. El barrido del 04 usaba `account/top/{theta,tfuel}` para
> decidir «qué contratos tienen saldo nativo». **Ese ranking está desfasado** y el
> método es inválido. Aquí está el inventario hecho por direcciones reales.

---

## 1. Por qué el método anterior no podía encontrar nada

`account/top/theta/200` baja hasta **203.719,650 THETA**. Pero:

| Contrato | THETA real | ¿Aparece en el top-200? |
|---|---|---|
| wTHETA `0xaf537fb7…` | **914.085,817** | **NO** |
| TFuelTokenBank `0xf8323908…` | 0 (224,5 M **TFUEL**) | no está en el top-100 de TFUEL |

wTHETA tiene 4,5× el saldo del puesto 200 y no aparece. **Conclusión: los rankings
del explorer son una foto vieja**, y «cero contratos en el top» no probaba nada.
Cualquier conclusión del 04 basada en ese ranking queda anulada.

También queda anulada la afirmación del 03 de que «el único contrato con THETA es
wTHETA»: no se sabía, se había inferido de un ranking roto.

---

## 2. Inventario por direcciones documentadas (fuente: `theta-metachain-guide/docs/3-mainnet`)

Único bloque de mainnet con direcciones verificables y con nombre. 21 direcciones,
estado real consultado una a una:

| Dirección | Qué es | THETA | TFUEL | Código |
|---|---|---|---|---|
| `0xf83239088B8766a27cD1f46772a2E1f88e916322` | **TFuelTokenBank** (puente metachain) | 0 | **224.576.487,97** | sí |
| `0xaf537fb7e4c77c97403de94ce141b7edb9f7fcf0` | **wTHETA** | **914.085,82** | 0 | sí |
| `0xb3d93735…18007e1b` | TNT20TokenBank | 0 | 0 | sí |
| `0xfe2d1be6…2cdbcdaf` | TNT721TokenBank | 0 | 0 | sí |
| `0xa31168d6…2e6b1542` | TNT1155TokenBank | 0 | 0 | sí |
| `0xb164c26f…82f272a7` | ChainRegistrarOnMainchain | 0 | 0 | sí |
| `0xf0716e62…9c2919d4` | ValidatorStakingManager | 0 | 0 | sí |
| `0x430a67c3…0466af2f` | TNT20 «auténtico» | 0 | 0 | sí |
| `0xa02fb057…a15c0677` | TNT721 «auténtico» | 0 | 0 | sí |
| `0x2E833968E5bB786Ae419c4d13189fB081Cc43bab` | «thetacli mainnet» | 100.003,4 | 21,77 | **EOA** |
| `0x29b2440d…2440A08f`, `0x47c5e408…`, `0x5a443704…`, `0x47e9Fbef…`, `0x8Be503bc…`, `0xBd770416…`, `0x7D7e270b…`, `0xd5125d7b…`, `0x1e006b53…`, `0x0ede92ca…` | genesis/testnet, no desplegadas | — | — | **no existen** |

**Resultado: de 21 direcciones documentadas, exactamente UNA tiene THETA nativo
(wTHETA) y ninguna otra es drenable.** El TFuelTokenBank tiene 224,5 M TFUEL (2× el
pool `0xd551…`), pero pertenece a la familia de token banks, ya descartada, y de
todos modos `0xCE` no permite quedarse el TFUEL (devuelve al `Source`).

Direcciones de la wallet oficial, resto: `0x3883f5e1…` (181.416 THETA, 742.450 TFUEL)
es **EOA** (`code` = keccak del vacío) ⇒ no ejecuta bytecode, no puede llamar a `0xCB`.

---

## 3. El criterio de explotabilidad, ya sin ambigüedad

Para que un contrato `V` con THETA sea drenable por esta vía tiene que existir una
ruta en `V` que ejecute:

```
<addr>.call(data)     |  <addr>.staticcall(data)  |  <addr>.delegatecall(data)
```

donde **`addr` y `data` los elige el atacante**, y `data[0:20]` = destinatario,
`data[20:52]` = cantidad. Y `CallerAddress` del frame será `V`.

Corolarios que eliminan casi todo el ecosistema:

- Si `addr` es fijo (`0xC9`, `0xCB`, un token concreto) → no sirve.
- Si `data` se construye con `abi.encodeWithSelector(...)` → los 4 bytes de selector
  desplazan el destinatario a `selector‖from[:16]`, que el atacante no elige → no sirve.
- Si `data` es **calldata crudo del usuario** y `addr` es un parámetro → **sí sirve**.
  Esto es exactamente un *ejecutor genérico* (`execute(target, data)` / multicall).

**wTHETA** (`0xaf537fb7…`, fuente verificada, leída entera) cae en el primer caso y en
el segundo: `_transferTheta` construye el array a mano (20 bytes de `dst` = `msg.sender`,
32 de `amount`), con `dst = msg.sender` y destino fijo `0xCB`, todo detrás de
`require(balanceOf(msg.sender) >= amount)` + `_burn` + `nonReentrant`. Balance 1:1,
sin excedente. **No es explotable.**

---

## 4. Estado de la búsqueda

Lo que he podido descartar **con dato**, no por opinión:

1. Top por saldo (THETA y TFUEL): inválido como enumerador (desfasado, §1).
2. 21 direcciones documentadas de mainnet: 1 con THETA (wTHETA), no explotable.
3. Contratos DeFi/Sushiswap/Uniswap de la org Theta: los repos son forks sin
   despliegue propio de direcciones; los `config.json` de `tdrop-marketplace` y
   `wyvern-v3` son direcciones de **Ethereum**, no de Theta.
4. Multicall3, Router02, SwapRouter, Permit2 (direcciones canónicas): **no existen**
   en Theta (`error_not_found`).
5. sTFuel/NodeManager del repo: no desplegados en las direcciones que declaran
   (`0x51900b0f…` es EOA; `0xedcc06ab…` no existe).
6. `.transfer` de 2.300 gas frente a `ThetaTransferGas = 21.000`: descarta todo
   contrato que pague con `transfer`/`send`.

Lo que **no** he podido hacer, y es donde queda el hueco:

- **No hay endpoint que liste contratos.** El explorer expone `account/update/:addr`
  (uno a uno), `transactions/blockRange` (542 chunks por 1.600 bloques, dominado por
  `type 0` del consenso) y rankings desfasados. Sin `eth_getCode` masivo ni RPC directo
  (el socket TLS a `:8443` y a `eth-rpc-api` está bloqueado en este entorno) no puedo
  barrer los ~millones de cuentas de la chain.

⇒ **El hueco concreto que falta por barrer**: un contrato en Theta que
(a) tenga THETA nativo y (b) exponga `execute(target, data)` o un multicall que
reenvíe `data` crudo. Si existe, es drenaje del 100 % de su THETA, irreversible y sin
firma de la víctima. Con lo que he podido enumerar, **hoy no lo he encontrado**.

---

## 5. Receta de detección para cuando haya RPC

Con acceso a `eth_getCode`/`debug_traceTransaction` sobre un nodo público (no desde
este entorno), el barrido decisivo es:

1. Enumerar contratos por actividad: para cada bloque, `tx.to` con `input` no vacío
   y `tx.type` de smart contract ⇒ conjunto de contratos vivos.
2. Para cada contrato, `eth_getBalance(addr)` > 0 en THETA.
3. Buscar en su bytecode la secuencia `0xCB` como destino de un `CALL`/`STATICCALL`
   **cuyo `input` provenga de calldata** (en traza: `input` idéntico a los argumentos
   de la tx, no una constante de 52 bytes construida en memoria).
4. Confirmar con `eth_call` simulando `execute(0xCB, attacker‖amount)` **sin valor**:
   si el balance del contrato baja, está drenable.

El paso 3 es el que separa wTHETA (array construido a mano) de un ejecutor genérico
(bytes del usuario). Es una diferencia observable en el bytecode, no una opinión.
