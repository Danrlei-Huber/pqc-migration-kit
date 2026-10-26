#!/usr/bin/env bash
# Mede a integração da biblioteca com o core (OmniTrustILM) e grava as evidências em integracao/evidencias.
# Roda, no core, os testes da prova de conceito sobre os mesmos certificados da área 09 e copia
# as matrizes observadas, os relatórios do Surefire e o ambiente para integracao/evidencias, separadas da
# campanha da biblioteca (evidencias/01..09).
# Uso: integracao/coletar-evidencias-core.sh [caminho-do-core]   (padrão: ../core)
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$(cd "${1:-$KIT/../core}" && pwd)"
OUT="$KIT/integracao/evidencias"
AREA09="$KIT/evidencias/09-politica-validacao"
FIXTURES="$CORE/src/test/resources/pqc/politica-validacao"
TESTES="PqcNativeBaselineITest,PqcHybridValidationITest,PqcTwinIssuerITest,HybridAltSignatureCheckTest,PqcValidationSettingsTest,CertificateValidationITest"
# Último commit do ramo antes do adaptador: o validador do core ainda é o original.
COMMIT_ANTES="${COMMIT_ANTES:-cf583bcf}"

if [ -n "$(git -C "$CORE" status --porcelain)" ]; then
  echo "A árvore do core tem alterações; as evidências precisam apontar para um commit." >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT/surefire"

# Os certificados do core têm de ser os mesmos bytes da área 09.
( cd "$AREA09" && sha256sum */raiz.der */folha.der | grep -v '^.* matriz/' ) > "$OUT/fixtures-area09.sha256"
( cd "$FIXTURES" && sha256sum */raiz.der */folha.der ) > "$OUT/fixtures-core.sha256"
if ! diff -q "$OUT/fixtures-area09.sha256" "$OUT/fixtures-core.sha256" >/dev/null; then
  echo "Os certificados do core divergem da área 09." >&2
  exit 1
fi
mv "$OUT/fixtures-core.sha256" "$OUT/fixtures.sha256"
rm "$OUT/fixtures-area09.sha256"

KIT_JAR="$HOME/.m2/repository/com/pqc/hybrid/pqc-hybrid-certificates/1.0.0-BETA/pqc-hybrid-certificates-1.0.0-BETA.jar"
INICIO="$(date -Iseconds)"
MVN_LOG="$(mktemp)"
WORKTREE="$(mktemp -d)"
limpar() {
  git -C "$CORE" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -f "$MVN_LOG"
}
trap limpar EXIT

# O log completo do Maven traz e-mails e caminhos locais; só as linhas de resultado vão para a evidência.
resultado() { grep -E 'Tests run:|BUILD (SUCCESS|FAILURE)|\[ERROR\]' "$MVN_LOG" || true; }

# 1. Linha de base medida no commit anterior ao adaptador, com o validador original do core.
git -C "$CORE" worktree add --detach "$WORKTREE" "$COMMIT_ANTES" >/dev/null 2>&1
set +e
( cd "$WORKTREE" && mvn -B test -Dtest=PqcNativeBaselineITest -Dsurefire.failIfNoSpecifiedTests=false ) > "$MVN_LOG" 2>&1
RC_ANTES=$?
set -e
resultado > "$OUT/resultado-testes-antes-da-integracao.txt"
cp -r "$WORKTREE/target/pqc-native-baseline" "$OUT/linha-de-base-antes-da-integracao"

# 2. Testes da integração no commit atual.
rm -rf "$CORE/target/pqc-native-baseline" "$CORE/target/pqc-policy-matrix" "$CORE/target/pqc-twin-issuer" \
  "$CORE/target/surefire-reports"
set +e
# clean: classes de uma compilação incremental anterior podem divergir das do código-fonte (nomes de lambdas
# sintéticas, verificados pelas regras de arquitetura).
( cd "$CORE" && mvn -B clean test -Dtest="$TESTES" -Dsurefire.failIfNoSpecifiedTests=false ) > "$MVN_LOG" 2>&1
RC=$?
set -e
resultado > "$OUT/resultado-testes.txt"

cp -r "$CORE/target/pqc-native-baseline" "$OUT/linha-de-base-modo-native"
cp -r "$CORE/target/pqc-policy-matrix" "$OUT/matriz-politicas"
cp -r "$CORE/target/pqc-twin-issuer" "$OUT/emissor-gemeo"

# O modo native deve reproduzir o validador original: os relatórios por cenário são comparados byte a byte.
if diff -r "$OUT/linha-de-base-antes-da-integracao" "$OUT/linha-de-base-modo-native" > "$OUT/equivalencia-native.txt"; then
  echo "Idênticos: os relatórios da linha de base no commit $COMMIT_ANTES (antes do adaptador) e no modo native do commit atual." \
    > "$OUT/equivalencia-native.txt"
fi
for t in ${TESTES//,/ }; do
  cp "$CORE"/target/surefire-reports/*"$t".txt "$OUT/surefire/" 2>/dev/null || true
  cp "$CORE"/target/surefire-reports/TEST-*"$t".xml "$OUT/surefire/" 2>/dev/null || true
done
# 3. Regras de arquitetura do core, que a integração não pode violar (só o resumo é guardado).
set +e
( cd "$CORE" && mvn -B test -Dtest='com.otilm.core.architecture.*Test' -Dsurefire.failIfNoSpecifiedTests=false ) \
  > "$MVN_LOG" 2>&1
RC_ARQ=$?
set -e
resultado | grep -E '^\[INFO\] Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+$|BUILD|\[ERROR\]' \
  > "$OUT/resultado-arquitetura.txt" || true

# <properties> guarda as propriedades do sistema e do git (e-mails, URL do remoto, caminhos locais).
sed -i '/<properties>/,/<\/properties>/d' "$OUT"/surefire/TEST-*.xml
if grep -rqE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' "$OUT"; then
  echo "Sobrou um endereço de e-mail nas evidências; revise antes de versionar:" >&2
  grep -rlE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' "$OUT" >&2
  exit 1
fi

# Linhas da área 09 e do core seguem a mesma ordem de cenários; a cadeia clássica só existe no core.
# Célula do core: só o status da folha (o da raiz fica em matriz-politicas/matriz-core.md).
{
  echo "| Cenário | JDK PKIX | openssl verify | core native | core strict | core hybrid-issuer | core hybrid-issuer {65,87} | core classical-only |"
  echo "|---|---|---|---|---|---|---|---|"
  paste -d'\t' \
    <(sed -n '3,8p' "$AREA09/matriz/matriz.txt" | awk -F'|' '{gsub(/^ +| +$/,"",$2);gsub(/^ +| +$/,"",$3);gsub(/^ +| +$/,"",$4);print $2"\t"$3"\t"$4}') \
    <(sed -n '3,8p' "$OUT/matriz-politicas/matriz-core.md" | awk -F'|' '{for(i=3;i<=7;i++){c=$i;gsub(/ \(raiz.*\)/,"",c);gsub(/^ +| +$/,"",c);printf "%s%s",c,(i<7?"\t":"\n")}}') \
    | awk -F'\t' '{printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7,$8}'
  sed -n '9p' "$OUT/matriz-politicas/matriz-core.md" | awk -F'|' '{printf "| Cadeia puramente clássica (controle) | — | — |";for(i=3;i<=7;i++){c=$i;gsub(/ \(raiz.*\)/,"",c);gsub(/^ +| +$/,"",c);printf " %s |",c};print ""}'
} > "$OUT/comparacao.md"

{
  echo "Commit do core: $(git -C "$CORE" rev-parse HEAD) (branch $(git -C "$CORE" branch --show-current))"
  echo "Commit do core antes da integração (linha de base): $(git -C "$CORE" rev-parse "$COMMIT_ANTES")"
  echo "Código de saída do Maven antes da integração: $RC_ANTES"
  echo "Código de saída do Maven das regras de arquitetura: $RC_ARQ"
  echo "Árvore do core antes e depois da medição: $([ -z "$(git -C "$CORE" status --porcelain)" ] && echo limpa || echo 'ALTERADA DURANTE A MEDICAO')"
  echo "Commit do kit: $(git -C "$KIT" rev-parse HEAD)"
  echo "Árvore do kit (src/ e pom.xml): $([ -z "$(git -C "$KIT" status --porcelain -- src pom.xml)" ] && echo limpa || echo 'com alteracoes')"
  echo "Jar do kit instalado: $(sha256sum "$KIT_JAR" | cut -d' ' -f1)"
  echo "Início: $INICIO"
  echo "Fim: $(date -Iseconds)"
  echo "Código de saída do Maven: $RC"
  java -version 2>&1 | head -2
  mvn -v 2>/dev/null | head -1
  echo "Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  echo "SO: $(uname -sr)"
  echo "Bouncy Castle resolvido no core:"
  ( cd "$CORE" && mvn -B -o dependency:tree -Dincludes=org.bouncycastle,com.pqc.hybrid ) 2>/dev/null \
    | grep -E 'bouncycastle|com.pqc' | sed 's/^\[INFO\] /  /'
} > "$OUT/ambiente.txt"

( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum ) > "$OUT/SHA256SUMS"
echo "Evidências gravadas em $OUT (mvn: antes=$RC_ANTES integração=$RC arquitetura=$RC_ARQ)"
[ "$RC_ANTES" -eq 0 ] && [ "$RC" -eq 0 ] && [ "$RC_ARQ" -eq 0 ]
