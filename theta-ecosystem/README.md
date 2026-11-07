# `theta-ecosystem/`

Clonado completo del ecosistema público de Theta.

| Fichero | Qué es |
|---|---|
| [`00-ANALISIS-ECOSISTEMA-THETA.md`](00-ANALISIS-ECOSISTEMA-THETA.md) | Análisis de la lógica de todos los componentes (consenso, ledger, subchains, RPC, explorer, wallets…) |
| [`repos.manifest.tsv`](repos.manifest.tsv) | Inventario: 57 repos con URL, branch, commit, fecha, tamaño y nº de archivos |
| [`sync-theta-repos.sh`](sync-theta-repos.sh) | Script idempotente para clonar/actualizar todo, o descubrir repos nuevos en la org |
| `repos/` | Los 57 repos clonados (shallow). **No versionado** — ver `.gitignore` |

```bash
# clonar o actualizar todo el ecosistema (~880 MB)
./theta-ecosystem/sync-theta-repos.sh

# solo el núcleo
./theta-ecosystem/sync-theta-repos.sh --only theta-protocol-ledger,theta-protocol-subchain

# ver qué repos nuevos publicó la org
./theta-ecosystem/sync-theta-repos.sh --discover

# historial completo en lugar de shallow
./theta-ecosystem/sync-theta-repos.sh --full
```

### Rutas más útiles

- Consenso: `repos/theta-protocol-ledger/consensus/{engine,guardian,elite_edge_node,validator}.go`
- Ejecución de txs: `repos/theta-protocol-ledger/ledger/execution/`
- EVM: `repos/theta-protocol-ledger/ledger/vm/`
- RPC: `repos/theta-protocol-ledger/rpc/`
- Interchain: `repos/theta-protocol-subchain/interchain/`
- Contratos precompilados de subchain: `repos/theta-protocol-subchain/interchain/contracts/predeployed/predeployed.go`
- SDK metachain: `repos/theta-metachain-guide/sdk/`
- Explorer (crawler/API/front): `repos/theta-infrastructure-ledger-explorer/backend/`, `.../frontend/`
