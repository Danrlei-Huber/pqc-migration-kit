#!/usr/bin/env bash
#
# run-examples.sh — compila a lib e executa os exemplos de fluxo no terminal.
#
# Cada exemplo é um programa com main() em com.pqc.hybrid.examples que demonstra
# um fluxo de uso da biblioteca, imprimindo os objetos produzidos/alterados a
# cada passo (chaves, assinatura byte[], certificados X.509, extensões Catalyst).
#
# Uso:
#   ./run-examples.sh              # lista os exemplos disponíveis
#   ./run-examples.sh all          # roda todos, em sequência
#   ./run-examples.sh flow         # roda o walkthrough ponta-a-ponta (recomendado)
#   ./run-examples.sh sign         # roda assinar/verificar
#   ./run-examples.sh <Classe>     # roda uma classe específica de examples/
#   ./run-examples.sh flow -v      # repassa args ao exemplo (-v = logs INFO)
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
PKG="com.pqc.hybrid.examples"
CP_FILE="target/cp.txt"

# Aliases curtos -> classe (FQN sem pacote)
declare -A ALIASES=(
  [flow]=LibraryFlowWalkthroughExample
  [cert]=GenerateCertificateExample
  [sign]=SignAndVerifyExample
  [algorithms]=AlgorithmExplorerExample
  [generation]=HybridCertificateGenerationExample
  [helper]=HybridCertificateHelper
)

# Ordem usada por "all"
ORDER=(algorithms flow cert sign generation helper)

ensure_build() {
  if [[ ! -d target/classes/com/pqc/hybrid/examples ]]; then
    echo -e "${YELLOW}⏳ Compilando (target/classes ausente)...${NC}"
    mvn -q compile
  fi
  if [[ ! -s "$CP_FILE" ]]; then
    echo -e "${YELLOW}⏳ Resolvendo classpath de runtime...${NC}"
    mvn -q dependency:build-classpath -Dmdep.outputFile="$CP_FILE" -DincludeScope=runtime
  fi
}

resolve_class() {
  local key="$1"
  if [[ -n "${ALIASES[$key]:-}" ]]; then
    echo "${ALIASES[$key]}"
  else
    echo "$key"   # assume nome de classe literal
  fi
}

run_one() {
  local class; class="$(resolve_class "$1")"; shift || true
  echo -e "\n${BLUE}▶ Executando ${PKG}.${class}${NC}"
  echo   "──────────────────────────────────────────────────────────────────"
  if java -cp "target/classes:$(cat "$CP_FILE")" "${PKG}.${class}" "$@"; then
    echo -e "${GREEN}✔ ${class} finalizou.${NC}"
  else
    echo -e "${RED}✗ ${class} falhou (exit $?).${NC}"; return 1
  fi
}

list_examples() {
  echo -e "${BLUE}Exemplos disponíveis:${NC}"
  for a in "${ORDER[@]}"; do
    printf "  ${GREEN}%-12s${NC} -> %s\n" "$a" "${ALIASES[$a]}"
  done
  echo
  echo "Uso: ./run-examples.sh [all|<alias>|<Classe>] [args do exemplo...]"
}

main() {
  if [[ $# -eq 0 ]]; then
    list_examples; exit 0
  fi
  ensure_build
  if [[ "$1" == "all" ]]; then
    for a in "${ORDER[@]}"; do run_one "$a"; done
  else
    run_one "$@"
  fi
}

main "$@"
