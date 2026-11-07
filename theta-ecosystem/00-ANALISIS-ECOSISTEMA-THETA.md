# Ecosistema Theta — clonado y análisis de lógica

Fecha del clonado: **2026-11-07** · Origen: organización GitHub [`thetatoken`](https://github.com/thetatoken) (todos los repos **públicos**, 57/57)
Modo: `git clone --depth 1 --single-branch` (2 repos con binarios gigantes, `edenai-apis` y `node-ffmpeg-installer`, clonados con `--filter=blob:none`).
Ubicación local: `theta-ecosystem/repos/` (fuera de control de versiones, ver `.gitignore`).

- Inventario exacto con commit/branch/fecha: [`repos.manifest.tsv`](repos.manifest.tsv)
- Script idempotente para reclonar o actualizar todo (y descubrir repos nuevos): [`sync-theta-repos.sh`](sync-theta-repos.sh)

```bash
./theta-ecosystem/sync-theta-repos.sh              # clona/actualiza los 57 repos
./theta-ecosystem/sync-theta-repos.sh --only theta-protocol-ledger,theta-protocol-subchain
./theta-ecosystem/sync-theta-repos.sh --discover   # avisa de repos nuevos en la org
./theta-ecosystem/sync-theta-repos.sh --list
```

Volumen: **~880 MB** de worktree, **~16.6k archivos**, **~600k líneas** de código (Go, JS/TS, Solidity, Python, C, Kotlin).

---

## 1. Mapa del ecosistema por capas

| Capa | Repos | Qué contiene realmente |
|---|---|---|
| **Protocolo / nodo mainnet** | `theta-protocol-ledger` | Cliente de referencia completo (Go): consenso multi-nivel BFT, ledger, EVM, RPC, P2P, snapshots |
| **Metachain / subchains** | `theta-protocol-subchain`, `theta-metachain-guide` | Cliente de subchain + interchain (witnesses, token banks TNT20/721/1155) + SDK JS y contratos |
| **Indexación / explorer** | `theta-infrastructure-ledger-explorer` | Crawler Mongo + API Express + frontend React (balances, txs, staking, precios) |
| **Adaptadores RPC** | `theta-eth-rpc-adaptor`, `theta-rosetta-rpc-adaptor` | Traducen JSON-RPC de Ethereum y la spec Rosetta sobre el RPC nativo `theta` |
| **Wallet / SDK / HW** | `theta-wallet-web`, `theta-ledger-app`, `app-ethereum`, `theta-protocol-delivery-lib`, `…-android-sdk-lib`, `useDApp` | Wallet web oficial, apps Ledger (C/Python), SDK de Theta Mesh Delivery (JS + Android), fork de useDApp |
| **Contratos / dApps** | `theta-openzeppelin-demo`, `theta-nft-demo`, `tdrop-governance`, `tdrop-marketplace`, `dapp-nft-staking-demo`, `tnt-20-token-example`, `tnt20-token-example`, `theta-erc20-token-sale`, `theta-hardhat-demo`, `theta-metamask-demo`, `theta-web3-examples`, `theta-drop-connect-example`, `theta-pass-example` | Solidity TNT-20/721/1155, staking NFT, gobernanza TDROP, ejemplos web3 |
| **Forks DeFi (para redes Theta)** | `sushiswap`, `uniswap-v2-core`, `uniswap-v2-periphery`, `uniswap-v3-core`, `uniswap-v3-periphery`, `wyvern-v3` | AMMs y exchange de NFTs adaptados |
| **EdgeCloud / EdgeStore / IA** | `theta-edge-store-demos`, `theta-edgecloud-chatbot-*`, `theta-edgecloud-sketch-to-3d-example`, `theta-edgecloud-virtual-try-on-example`, `theta-edge-cloud-ai-characters-public`, `sketch-to-3d-demo`, `on-demand-api-mcp`, `theta-video-api-demo`, `videojs-theta-plugin-example`, `edenai-apis`, `node-ffmpeg-installer` | Demos de video/streaming descentralizado, chatbots, IA generativa, MCP |
| **Infra / despliegue** | `aws-blockchain-node-runners`, `theta-launcher`, `guardian-mainnet-guide`, `guardian-testnet-guide`, `theta-mainnet-integration-guide`, `theta-foodcourt`, `cloud-gpus.github.io` | CDK de AWS, script de arranque con snapshot, guías de nodos Guardian |
| **Metadata** | `chains`, `tokens-list`, `theta-blocks` | chainID/networkID, listas de tokens, metadata de bloques |
| **Legado** | `sliver-integration-transaction-signer`, `sliver-integration-transaction-service-deprecated`, `theta-tool-ethereum-erc20-snapshot` | Integración SLIVER (2018-19) y herramienta de snapshot ERC20 |

---

## 2. Núcleo: `theta-protocol-ledger` (nodo mainnet)

Binarios: `theta` (nodo) y `thetacli` (CLI/wallet). Versión en `version/version_number.txt` → **4.1.4**. Módulo Go: `github.com/thetatoken/theta`.

### 2.1 Consenso — multi-level BFT (`consensus/`)
Dos motores que se combinan para finalidad en dos niveles:

- **`guardian.go` — GuardianEngine**: votación de guardianes (proof-of-stake con TFuel); rondas de longitud configurable (`guardian.roundLength`), votos agregados por firma BLS (`crypto/bls`).
- **`elite_edge_node.go` — EliteEdgeNodeEngine**: votación de los Elite Edge Nodes (los que aportan cómputo de borde); maneja votos individuales, votos agregados y validación multi-ronda (`checkMultipliesForRound`, `maxMultiply`).
- **`engine.go` — ConsensusEngine**: orquesta ambos motores, timers de voto/epoch, canal de bloques finalizados, arranque y sincronización (`hasSynced`).
- **`validator.go`**: `MaxValidatorCount = 31`, `FixedValidatorManager` y selección de proponente por altura/hash.
- **`state.go`**: estado persistente de consenso (alturas, último bloque finalizado).

### 2.2 Ledger, estado y ejecución (`ledger/`)
- **Tipos de transacción** (`ledger/types/serialization.go`, `TxType`): `TxCoinbase, TxSlash, TxSend, TxReserveFund, TxReleaseFund, TxServicePayment, TxSplitRule, TxSmartContract, TxDepositStake, TxWithdrawStake, TxDepositStakeV2, TxStakeRewardDistribution`.
- **Ejecutores** (`ledger/execution/`): un fichero por tipo (`tx_send.go`, `tx_deposit_stake.go`, `tx_withdraw_stake.go`, `tx_slash.go`, `tx_smart_contract.go`, `tx_coinbase.go`, `tx_reserve_fund.go`, `tx_release_fund.go`, `tx_service_payment.go`, `tx_split_rule.go`, `tx_stake_reward_distribution.go`) + `executor.go` que los despacha.
- **Estado** (`ledger/state/`): `StoreView` (vista MVCC sobre el trie), pools de Elite Edge Nodes, reglas de reparto de recompensas (`stake_reward_distribution_rule_set.go`), claves versionadas (`keys.go`).
- **Reglas de reparto** (`ledger/types/split_rule.go`): el "split rule" es la pieza que paga a los nodos de borde por el tráfico de video servido.
- **EVM** (`ledger/vm/`): fork de la máquina virtual de go-ethereum (intérprete, jump/memory/stack tables, gas tables, precompilados, `hardening/`), más `asm/` y `params/`.

### 2.3 Blockchain y almacenamiento (`blockchain/`, `store/`)
- `blockchain/chain.go` — cadena principal y bifurcaciones; `tx.go`, `vote.go` — envoltorios firmados.
- `store/` — microservicios de almacenamiento: `database/`, `kvstore/`, `treestore/`, **`trie/`** (Merkle Patricia), **`rollingdb/`** (retención por *reference counting* + poda de histórico, clave para correr en hardware modesto).
- `snapshot/` — snapshots de estado comprimidos para arranque rápido (lo usa `theta-launcher`).

### 2.4 Red P2P (`p2p/`, `p2pl/`, `dispatcher/`, `netsync/`)
- `p2p/` implementación propia: `messenger/`, `peer/`, `connection/`, `nat/`, `netutil/`, `simulation/`; multiplexado con prioridades y límites de frame (hay commits recientes de seguridad `security/p2p-frame-limits`).
- `p2pl/` variante libp2p (`messenger/`, `transport/`, `peer/`).
- `dispatcher/` + `netsync/` — propagación de bloques/votos y sincronización de ramas/inventario.
- Puertos por defecto: P2P **50001** (`p2p.port`), RPC **16888** (`rpc.port`, bind `0.0.0.0`), descubrimiento de peers opcional en **16889**.

### 2.5 RPC (`rpc/`)
Servicio JSON-RPC (net/rpc + codec `jsonrpc2` sobre HTTP/WebSocket), namespace **`theta`**. Métodos principales:
`GetStatus, GetVersion, GetAccount, GetBlock, GetBlockByHeight, GetBlocksByRange, GetTransaction, GetPendingTransactions, GetPeers, GetPeerURLs, CallSmartContract, GetCode, GetStorageAt, GetSplitRule, ReportPeers, BroadcastRawTransaction(+Async), BroadcastRawEthTransaction(+Async), GetVcpByHeight, GetGcpByHeight, GetEenpByHeight, GetEenpStakeByHeight, GetEliteEdgeNodeStakeReturnsByHeight, GetGuardianInfo, GetStakeRewardDistributionByHeight, TraceBlocks, BackupChain, BackupSnapshot, BackupChainCorrection`.
Protecciones: límite de conexiones, timeouts, umbral/cuota para consultas pesadas de bloques (`GetBlocksHeavyQueryThreshold`, `MaxHeavyGetBlocksQueryCount`), métodos admin desactivados por defecto y listener separado para peer discovery.

### 2.6 CLI y herramientas (`cmd/`, `integration/`)
- `thetacli query …` (account, block, tx, vcp, gcp, eenp, guardian, split_rule, srdrs, stake_return, peers, status) y `thetacli tx …` (send, reserve_fund, release_fund, deposit_stake, withdraw_stake, smart_contract, split_rule, stake_reward_distribution).
- `integration/`: entornos `privatenet/ testnet/ testnet_amber/ testnet_sapphire/ mainnet/` con `config.yaml`, genesis, keys y snapshots; `e2etest/` para pruebas end-to-end; `tools/` con `generate_genesis`, `import_chain`, `dump_storeview`, `query_db`, `inspect_data`, `sign_hex_msg`, `encrypt_sk`, `hex_obj_parser`.
- `wallet/`: `softwallet/` (keystore) y `coldwallet/` (firma offline).
- `docs/`: whitepaper técnico y el informe **multi-level BFT** en PDF.

---

## 3. Subchains / Metachain: `theta-protocol-subchain`

Módulo `github.com/thetatoken/thetasubchain` — un nodo derivado del ledger pero con su propia cadena, fee model y puente a la mainchain ("chain of chains").

- **`interchain/`** (la lógica diferencial):
  - `witness/metachain_witness.go` + `metachain_witness_state.go`: escanean la mainchain (vía ETH-RPC adaptor) desde `subchain.mainchainWitenessStartScanHeight`, cachean eventos y los materializan en la subchain (`mw/lwqh/<chainID>` guarda la última altura consultada por cadena origen).
  - `orchestrator/orchestrator.go`: orquesta witnesses, propuestas y ciclo de vida (`ChainOrchestrator: Start/Stop/Wait`).
  - `utils/inter_chain_event_cache.go`, `eth_rpc_utils.go`: caché de eventos cross-chain y cliente RPC.
  - `contracts/predeployed/predeployed.go`: **bytecode precompilado** de los contratos del sistema (ChainRegistrarOnSubchain, TFuelTokenBank, TNT20/721/1155 TokenBank, BalanceChecker) inyectado en génesis; `contracts/accessors/` son los bindings Go (TNT20/721/1155 banks, vouchers, wrapped THETA, subchain governance token, fee token bank).
- **`ledger/`**: ejecutores reducidos (`tx_send`, `tx_coinbase`, `tx_smart_contract`, `tx_validator_set_update`) y su propia EVM.
- **`eth/rpc/`**: servidor **Ethereum JSON-RPC nativo** (eth_call, logs, subscriptions, filters) — la subchain habla directamente el dialecto Ethereum.
- **Modelo de gas/fees**: en subchains el TFuel de la mainchain se representa como token puenteado (`TFuelTokenBank`) y se cobran fees tokenizados; validadores hacen stake vía `ValidatorStakeManager` / `ValidatorCollateralManager` (ver ABIs del SDK).
- **Config clave** (`common/config.go`): `subchain.mainchainTFuelTB`, `…TNT20TB`, `…TNT721TB`, `…TNT1155TB`, `subchain.mainchainEthRpcURL`, `subchain.mainchainBlockIntervalInSeconds`, `subchain.mainchainWitenessStartScanHeight`.
- **`integration/privatenet/node`** + `subchain_generate_genesis` (con `init_validator_set.json`) para levantar una subchain privada; `privatenet_two_subchains/` y `privatenet_multinode/` para escenarios multi-subchain.
- **`theta-metachain-guide`** complementa: `sdk/contracts/*.json` (ABIs de ERC20/721/1155, ChainRegistrar, TokenBanks, ValidatorStakeManager…) y `sdk/js/` (registerSubchain, depositStake, withdrawStake, transferTNT20/721/1155, mintMockWrappedTheta, claimStake…), más demos de transferencia cross-chain y de token de gobernanza.

---

## 4. Indexación: `theta-infrastructure-ledger-explorer`

- `backend/crawler/`: jobs por dominio — `read-block.js`, `read-tx-history.js`, `read-accounts.js`, `read-previous-token.js`, `read-previous-fee.js`, `accounting.js`, `update-token-summary.js`; escribe en **MongoDB**; incluye `libs/Theta.js` (build de theta.js embebido).
- `backend/explorer-api/`: Express con 12 routers — account, accountTx, accounting, activeAct, blocks, price, rewardDistribution, smartContract, stake, supply, token, transactions.
- `backend/explorer-helper/`: utilidades de agregación; `frontend/`: React + webpack (`docs/api.md` documenta la API).

## 5. Adaptadores RPC

- **`theta-eth-rpc-adaptor`** (`rpc/ethrpc/*.go`): `eth_accounts, eth_blockNumber, eth_call, eth_chainId, eth_estimateGas, eth_gasPrice, eth_getBalance, eth_getBlockByHash/Number, eth_getBlockTransactionCountByNumber, eth_getCode, eth_getLogs, eth_getStorageAt, eth_getTransactionBy…, eth_sendRawTransaction, …` y traduce cada llamada al RPC nativo (`common/utils.go: GetThetaRPCEndpoint`, `HandleThetaRPCResponse`). Es el puente que usan MetaMask/Hardhat/Foundry y los witnesses de subchain.
- **`theta-rosetta-rpc-adaptor`**: implementación de la spec Rosetta de Coinbase (network/block/account/construction/mempool) sobre Theta.

## 6. Wallet, SDK y hardware

- **`theta-wallet-web`**: React; depende de `@thetalabs/theta-js`, `@thetalabs/wallet-metadata`, `@ledgerhq/hw-app-eth`, `@trezor/connect-web` (soporte Ledger y Trezor).
- **`theta-ledger-app`** (C) y **`app-ethereum`** (C, 109 ficheros .c): apps de dispositivo Ledger para firmar transacciones Theta/Ethereum, con tests en Python (`speculos`).
- **`theta-protocol-delivery-lib`** (JS) y **`theta-protocol-delivery-android-sdk-lib`** (Kotlin): SDK de **Theta Mesh Delivery** — malla P2P para repartir video entre viewers; ejemplos `livestream/` y `slivertv/`.

## 7. EdgeCloud / EdgeStore / IA

Demos y APIs para el cómputo de borde: `theta-edge-store-demos` (video, uploads, playback), `theta-edgecloud-chatbot-*` (RAG/knowledge base), `sketch-to-3d`, `virtual-try-on`, `theta-edge-cloud-ai-characters-public` (poker con NPCs IA), `on-demand-api-mcp` (servidor MCP, TS), `theta-video-api-demo` + `videojs-theta-plugin-example` (player), y los forks `edenai-apis` (APIs de IA multimodales, Python) y `node-ffmpeg-installer` (transcodificación).

## 8. Infra y despliegue

- `aws-blockchain-node-runners`: CDK TypeScript (guardian/EEN/explorer) con docs de despliegue en AWS.
- `theta-launcher`: script Python que descarga el último snapshot y arranca el nodo.
- `guardian-mainnet-guide` / `guardian-testnet-guide` / `theta-mainnet-integration-guide`: guías operativas (requisitos, systemd, puertos, troubleshooting) y ejemplos (JS/Java).

## 9. Metadata

`chains` (Kotlin + JSON con chainID/networkID por red), `tokens-list`, `theta-blocks`.

---

## 10. Observaciones técnicas útiles

1. **Todo el nodo es Go con módulos** (`go.mod`), pero el README aún menciona `glide`; el build real es `make install` con Go ≥1.14 (requiere `cgo` para BLS/secp256k1).
2. **Espacios de nombres divergentes**: `theta-protocol-ledger` usa el módulo `github.com/thetatoken/theta`; la subchain `github.com/thetatoken/thetasubchain`. Comparten tipos por copia, no por import cruzado → los cambios de protocolo hay que replicarlos en ambos.
3. **Puntos de entrada para leer la lógica**: `consensus/engine.go` → `ledger/execution/executor.go` → `ledger/state/storeview.go`; y en subchain `interchain/witness/metachain_witness.go` → `interchain/orchestrator/orchestrator.go`.
4. **Seguridad**: el RPC admin está desactivado por defecto, hay cuotas para consultas pesadas y listener separado de peer discovery; el P2P limita tamaño de frame (commit reciente). Aun así, exponer `16888` a Internet requiere reverse proxy + rate limiting.
5. **Repos "de terceros" clonados** (`edenai-apis`, `node-ffmpeg-installer`, `uniswap-*`, `sushiswap`, `wyvern-v3`, `useDApp`, `aws-blockchain-node-runners`) son forks: sirven como referencia de integración, no como código propio de Theta.
6. **Deprecados**: `sliver-integration-transaction-service-deprecated` (2019) y el flujo SLIVER en general están obsoletos frente a Theta Mesh Delivery.

---

## 11. Cómo compilar y arrancar el nodo (resumen del propio repo)

```bash
cd theta-ecosystem/repos/theta-protocol-ledger     # o el checkout raíz de este repo
export GO111MODULE=on
make install            # genera $GOBIN/theta y $GOBIN/thetacli
make test_unit
theta start --config=../privatenet/node         # nodo local con genesis de privatenet
thetacli query status --endpoint=localhost:16888
```

Para una subchain:

```bash
cd theta-ecosystem/repos/theta-protocol-subchain
make install            # thetasubchain + thetasubcli
cd integration/privatenet/node && subchain_generate_genesis \
  -mainchainID=privatenet -subchainID=tsub360777 \
  -initValidatorSet=./data/init_validator_set.json -genesis=./snapshot
```
