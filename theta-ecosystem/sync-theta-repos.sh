#!/usr/bin/env bash
# Sincroniza (clona o actualiza) TODO el ecosistema público de Theta desde GitHub
# dentro de theta-ecosystem/repos/. Idempotente: si el repo ya existe, hace update.
#
# Uso:
#   ./theta-ecosystem/sync-theta-repos.sh              # clona/actualiza todos
#   ./theta-ecosystem/sync-theta-repos.sh --depth 1    # shallow (por defecto 1)
#   ./theta-ecosystem/sync-theta-repos.sh --full       # historial completo
#   ./theta-ecosystem/sync-theta-repos.sh --only theta-protocol-ledger,theta-protocol-subchain
#   ./theta-ecosystem/sync-theta-repos.sh --discover   # descubre repos nuevos de la org vía API
#   ./theta-ecosystem/sync-theta-repos.sh --list       # lista el set actual
#
# Nota: los repos se guardan fuera del control de versiones (ver .gitignore).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${ROOT}/repos"
ORG="${THETA_ORG:-thetatoken}"
DEPTH=1
ONLY=""
DISCOVER=0
LIST=0
JOBS="${JOBS:-4}"

while [ $# -gt 0 ]; do
  case "$1" in
    --depth) DEPTH="${2:-1}"; shift 2 ;;
    --full) DEPTH=""; shift ;;
    --only) ONLY=",${2:-},",; shift 2 ;;
    --dest) DEST="${2:-}"; shift 2 ;;
    --org) ORG="${2:-}"; shift 2 ;;
    --discover) DISCOVER=1; shift ;;
    --list) LIST=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "opción desconocida: $1" >&2; exit 2 ;;
  esac
done

REPOS=(
  # --- Núcleo de protocolo / nodos / subchains ---
  theta-protocol-ledger
  theta-protocol-subchain
  theta-infrastructure-ledger-explorer
  theta-eth-rpc-adaptor
  theta-rosetta-rpc-adaptor
  theta-launcher
  aws-blockchain-node-runners
  # --- SDKs / wallet / delivery ---
  theta-wallet-web
  theta-protocol-delivery-lib
  theta-protocol-delivery-android-sdk-lib
  theta-ledger-app
  app-ethereum
  useDApp
  # --- Guías y documentación técnica ---
  theta-metachain-guide
  theta-mainnet-integration-guide
  guardian-mainnet-guide
  guardian-testnet-guide
  theta-edge-cloud-platform-services-api
  # --- Contratos y demos ---
  theta-openzeppelin-demo
  theta-nft-demo
  theta-hardhat-demo
  theta-metamask-demo
  theta-web3-examples
  theta-drop-connect-example
  theta-pass-example
  dapp-nft-staking-demo
  tnt-20-token-example
  tnt20-token-example
  theta-erc20-token-sale
  tdrop-governance
  tdrop-marketplace
  theta-tool-ethereum-erc20-snapshot
  # --- Forks de DeFi / protocolos ---
  sushiswap
  uniswap-v2-core
  uniswap-v2-periphery
  uniswap-v3-core
  uniswap-v3-periphery
  wyvern-v3
  # --- EdgeCloud / EdgeStore / medios ---
  theta-edge-store-demos
  theta-edgecloud-chatbot-example
  theta-edgecloud-chatbot-knowledge-example
  theta-edgecloud-sketch-to-3d-example
  theta-edgecloud-virtual-try-on-example
  theta-edge-cloud-ai-characters-public
  sketch-to-3d-demo
  on-demand-api-mcp
  theta-video-api-demo
  videojs-theta-plugin-example
  edenai-apis
  node-ffmpeg-installer
  # --- Metadata / misc / legado ---
  chains
  tokens-list
  theta-blocks
  theta-foodcourt
  cloud-gpus.github.io
  sliver-integration-transaction-signer
  sliver-integration-transaction-service-deprecated
)

if [ "$LIST" = "1" ]; then printf '%s\n' "${REPOS[@]}"; exit 0; fi

mkdir -p "$DEST"

clone_or_update() {
  local name="$1"
  local dir="${DEST}/${name}"
  local url="https://github.com/${ORG}/${name}.git"
  if [ -d "${dir}/.git" ]; then
    git -C "$dir" fetch --quiet --all --prune || { echo "FETCH FAIL ${name}"; return 1; }
    local br
    br=$(git -C "$dir" rev-parse --abbrev-ref HEAD)
    git -C "$dir" rebase --quiet "origin/${br}" >/dev/null 2>&1 || git -C "$dir" merge --ff-only --quiet "origin/${br}" >/dev/null 2>&1
    echo "updated  ${name} @ $(git -C "$dir" rev-parse --short HEAD)"
  else
    local args=(clone --quiet --single-branch)
    [ -n "$DEPTH" ] && args+=(--depth "$DEPTH")
    if git "${args[@]}" "$url" "$dir" >/dev/null 2>&1; then
      echo "cloned   ${name} @ $(git -C "$dir" rev-parse --short HEAD)"
    else
      # fallback: clon filtrado sin blobs (repos con binarios enormes)
      git clone --quiet --depth 1 --single-branch --filter=blob:none "$url" "$dir" >/dev/null 2>&1 \
        && echo "cloned*  ${name} @ $(git -C "$dir" rev-parse --short HEAD)" \
        || { echo "FAIL     ${name}"; return 1; }
    fi
  fi
}
export -f clone_or_update
export DEST ORG DEPTH

selected=()
for r in "${REPOS[@]}"; do
  if [ -n "$ONLY" ] && [[ "$ONLY" != *",$r,"* ]]; then continue; fi
  selected+=("$r")
done

printf '%s\n' "${selected[@]}" | xargs -P "$JOBS" -I{} bash -c 'clone_or_update "$@"' _ {}

if [ "$DISCOVER" = "1" ]; then
  echo "== Descubriendo repos nuevos de la org ${ORG} =="
  command -v python3 >/dev/null || { echo "python3 requerido para --discover"; exit 1; }
  for page in 1 2 3 4; do
    curl -fsSL "https://api.github.com/orgs/${ORG}/repos?per_page=100&page=${page}" || break
  done | python3 -c '
import sys, json
dec = json.JSONDecoder(); txt = sys.stdin.read(); i = 0; names = set()
while i < len(txt):
    t = txt[i:].lstrip()
    if not t: break
    off = len(txt[i:]) - len(t); obj, end = dec.raw_decode(t); i += off + end
    for r in obj: names.add(r["name"])
known = set(open("'"${ROOT}"'/sync-theta-repos.sh").read().split())
new = sorted(n for n in names if n not in known)
print("\n".join(new) if new else "(sin repos nuevos)")
'
fi

echo "== Listo. Repos en ${DEST} =="
find -L "$DEST" -maxdepth 1 -mindepth 1 -type d | wc -l
du -shL "$DEST"
