#!/usr/bin/env bash
# Mede a integração da biblioteca com o core (OmniTrustILM) e grava a área de evidências 10.
# Roda, no core, os testes da prova de conceito sobre os mesmos certificados da área 09 e copia
# as matrizes observadas, os relatórios do Surefire e o ambiente para evidencias/10-integracao-core.
# Uso: integracao/coletar-evidencias-core.sh [caminho-do-core]   (padrão: ../core)
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$(cd "${1:-$KIT/../core}" && pwd)"
OUT="$KIT/evidencias/10-integracao-core"
AREA09="$KIT/evidencias/09-politica-validacao"
FIXTURES="$CORE/src/test/resources/pqc/politica-validacao"
TESTES="PqcNativeBaselineITest,PqcHybridValidationITest,HybridAltSignatureCheckTest,PqcValidationSettingsTest,CertificateValidationITest"

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
# O log completo do Maven traz e-mails e caminhos locais; só as linhas de resultado vão para a evidência.
rm -rf "$CORE/target/pqc-native-baseline" "$CORE/target/pqc-policy-matrix" "$CORE/target/surefire-reports"
MVN_LOG="$(mktemp)"
set +e
( cd "$CORE" && mvn -B test -Dtest="$TESTES" -Dsurefire.failIfNoSpecifiedTests=false ) > "$MVN_LOG" 2>&1
RC=$?
set -e
grep -E 'Tests run:|BUILD (SUCCESS|FAILURE)|\[ERROR\]' "$MVN_LOG" > "$OUT/resultado-testes.txt" || true
rm -f "$MVN_LOG"

cp -r "$CORE/target/pqc-native-baseline" "$OUT/linha-de-base-nativa"
cp -r "$CORE/target/pqc-policy-matrix" "$OUT/matriz-politicas"
for t in ${TESTES//,/ }; do
  cp "$CORE"/target/surefire-reports/*"$t".txt "$OUT/surefire/" 2>/dev/null || true
  cp "$CORE"/target/surefire-reports/TEST-*"$t".xml "$OUT/surefire/" 2>/dev/null || true
done
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
echo "Evidências gravadas em $OUT (mvn exit=$RC)"
exit $RC
