#!/usr/bin/env python3
"""
07 - Barrido de la chain Theta (chainId 361) para el bug readOnly de run().

El modelo del sandbox donde se escribio esto NO tiene salida a los RPC de Theta
(allowlist de red), asi que este script se ejecuta donde si la haya. Lista los
RPC publicos verificados por el usuario.

Uso:
    pip install requests
    python3 07-sweep-theta-rpc.py            # barrido dirigido (rapido)
    python3 07-sweep-theta-rpc.py --blocks 2000

Que hace:
  1. Sembra el conjunto de candidatos: contratos conocidos, contrapartes de
     transacciones recientes y destinatarios de los pools grandes.
  2. Filtra con eth_getBalance -> solo THETA > 0.
  3. Para cada candidato con THETA, busca en su BYTECODE el patron peligroso:
     un CALL/STATICCALL/DELEGATECALL cuyo destino pueda venir de calldata.
  4. Imprime una tabla priorizada.

Nota importante sobre el criterio: el precompilado 0xCB debita
`contract.CallerAddress`, NO `contract.self`. Por tanto NO hace falta que la
victima envie valor al atacante: basta con que la victima ejecute codigo del
atacante moviendo CERO valor, y que ese codigo haga
`0xCB.delegatecall(attacker || amount)`. Ver 06, seccion 6.4.
"""

import argparse
import json
import sys
import time

import requests

RPCS = [
    "https://eth-rpc-api.thetatoken.org/rpc",
    "https://eth-rpc-api.thetatoken.org",
    "https://www.thetascan.io/api/eth-rpc",
    "https://361.rpc.thirdweb.com",
]

CHAIN_ID = 0x169  # 361
THETA_PRECOMPILE = "cb"  # 0xCB transferTheta (debits CallerAddress)

# Semillas: contratos conocidos de Theta mainnet.
SEEDS = [
    "0xaf537fb7e4c77c97403de94ce141b7edb9f7fcf0",  # wTHETA (914k THETA, limpio)
    "0xd551fd014d98edf6362c0c4e141dd7331888d9f8",  # pool 234M TFUEL
    "0xf83239088b8766a27cd1f46772a2e1f88e916322",  # TFuelTokenBank
    "0xe23b154f5f46a8ac3a1ab4cc7429a3b4d1bd4a92",  # router ThetaSwap
    "0xaf5c5da50befa5d30e2ebe283bec50df432a0dc4",  # pool TDROP/TFUEL
    "0xb164c26fd7970746639151a8c118cce282f272a7",  # ChainRegistrar
    "0xf0716e6221618137fb05d72450e0fc8d9c2919d4",  # ValidatorStakingManager
    "0xb3d93735de018ad48122bf7394734a7d18007e1b",  # TNT20TokenBank
    "0xfe2d1be6bd9d342cfa59e75290f9b0b42cdbcdaf",  # TNT721TokenBank
    "0xa31168d669112937b0826b1bf15f0eb12e6b1542",  # TNT1155TokenBank
    "0x8188d97c39c5c642f6f1e363466dcf554f344f67",  # jackpot THETA
    "0x595955c9a0368cc3aa4c084069c01f9399f5bba8",  # jackpot multi-chain
    "0x4dc08b15ea0e10b96c41aec22fab934ba15c983e",  # WTFuel
]


class RPC:
    def __init__(self, urls):
        self.urls = list(urls)
        self.i = 0
        self.session = requests.Session()

    def call(self, method, params, retries=3):
        last = None
        for attempt in range(retries):
            url = self.urls[self.i % len(self.urls)]
            try:
                r = self.session.post(
                    url,
                    json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                    headers={"Content-Type": "application/json"},
                    timeout=25,
                )
                r.raise_for_status()
                body = r.json()
                if "error" in body:
                    raise RuntimeError(body["error"])
                return body.get("result")
            except Exception as exc:  # rota de RPC y reintenta
                last = exc
                self.i += 1
                time.sleep(0.4 * (attempt + 1))
        raise RuntimeError(f"{method} fallo en todos los RPC: {last}")


def get_balance(rpc, addr):
    return int(rpc.call("eth_getBalance", [addr, "latest"]), 16)


def get_code(rpc, addr):
    return rpc.call("eth_getCode", [addr, "latest"]) or "0x"


def is_contract(code):
    if not code or code == "0x":
        return False
    # keccak256("") es el hash de una EOA sin codigo
    return len(code) > 2


def find_callsite_patterns(code_hex):
    """
    Heuristica sobre bytecode: localiza CALL (0xF1), CALLCODE (0xF2),
    DELEGATECALL (0xF4) y STATICCALL (0xFA) y mira si en las ~20 posiciones
    anteriores aparece PUSHn con un destino que NO sea el precompilado, o si el
    gas viene de GAS (0x5A) en vez de un PUSH constante.

    Devuelve lista de dicts con lo que ha visto. No es un decompilador: sirve
    para priorizar, y cada hallazgo se confirma con traza/eth_call.
    """
    b = bytes.fromhex(code_hex[2:])
    out = []
    i = 0
    while i < len(b):
        op = b[i]
        if op == 0x5A:  # GAS
            pass
        if op in (0xF1, 0xF2, 0xF4, 0xFA):
            window = b[max(0, i - 24):i]
            pushes = []
            j = 0
            while j < len(window):
                wop = window[j]
                if 0x60 <= wop <= 0x7F:
                    n = wop - 0x5F
                    pushes.append(window[j + 1:j + 1 + n])
                    j += 1 + n
                else:
                    j += 1
            has_gas_op = 0x5A in window
            out.append({
                "pc": i,
                "op": {0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL", 0xFA: "STATICCALL"}[op],
                "gas_from_GAS_op": has_gas_op,
                "pushes": [p.hex() for p in pushes][-4:],
            })
            # no seguimos byte a byte dentro de PUSH para no desalinear
        if 0x60 <= op <= 0x7F:
            i += 1 + (op - 0x5F)
        else:
            i += 1
    return out


def suspicious(calls):
    """
    Marca las llamadas cuyo destino parece variable (no un PUSH2 fijo de 20
    bytes con un contrato conocido) o cuyo gas viene de la GAS op (gas ilimitado).
    """
    hits = []
    for c in calls:
        fixed_dest = any(len(p) in (32, 40) and p[-40:] in (
            "00000000000000000000000000000000000000cb",
            "00000000000000000000000000000000000000c9",
        ) for p in c["pushes"])
        if c["gas_from_GAS_op"] and not fixed_dest:
            hits.append(c)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", type=int, default=0,
                    help="ademas de las semillas, recorrer N bloques recientes")
    ap.add_argument("--out", default="sweep-result.json")
    args = ap.parse_args()

    rpc = RPC(RPCS)

    # 1) sanity: chainId
    cid = rpc.call("eth_chainId", [])
    print(f"RPC ok, chainId = {cid} (esperado {hex(CHAIN_ID)})")
    if int(cid, 16) != CHAIN_ID:
        print("AVISO: chainId inesperado, abortando")
        sys.exit(1)

    candidates = list(SEEDS)

    # 2) si se pide, anadir direcciones vistas en bloques recientes
    if args.blocks:
        head = int(rpc.call("eth_blockNumber", []), 16)
        print(f"head = {head}; recorriendo {args.blocks} bloques")
        for n in range(head, max(0, head - args.blocks), -1):
            blk = rpc.call("eth_getBlockByNumber", [hex(n), True])
            if not blk:
                continue
            for tx in blk.get("transactions", []):
                if tx.get("to"):
                    candidates.append(tx["to"].lower())
                if tx.get("from"):
                    candidates.append(tx["from"].lower())
            if n % 50 == 0:
                print(f"  bloque {n}: {len(set(candidates))} candidatos")

    candidates = sorted(set(c.lower() for c in candidates))
    print(f"{len(candidates)} candidatos unicos")

    rows = []
    for idx, addr in enumerate(candidates, 1):
        try:
            bal = get_balance(rpc, addr)
            if bal == 0:
                continue
            code = get_code(rpc, addr)
            if not is_contract(code):
                continue  # EOA: no ejecuta bytecode, no puede llamar a 0xCB
            calls = find_callsite_patterns(code)
            hits = suspicious(calls)
            rows.append({
                "address": addr,
                "theta": bal / 1e18,
                "code_size": (len(code) - 2) // 2,
                "calls": len(calls),
                "suspicious": len(hits),
                "detail": hits[:6],
            })
            print(f"[{idx}/{len(candidates)}] {addr}  THETA={bal/1e18:,.2f}  "
                  f"calls={len(calls)}  sospechosas={len(hits)}")
        except Exception as exc:
            print(f"[{idx}] {addr}  ERROR {exc}")

    rows.sort(key=lambda r: (-r["suspicious"], -r["theta"]))
    with open(args.out, "w") as fh:
        json.dump(rows, fh, indent=2)

    print("\n=== CONTRATOS CON THETA (ordenados por riesgo) ===")
    for r in rows[:40]:
        print(f"{r['address']}  THETA={r['theta']:>14,.2f}  "
              f"tamano={r['code_size']:>6}  sospechosas={r['suspicious']}")
    print(f"\nGuardado en {args.out}")


if __name__ == "__main__":
    main()
