#!/usr/bin/env bash
# Mede o HybridOperationsBenchmark com a máquina o mais ociosa possível.
# Para o contêiner Ollama durante a medição e o religa ao sair (inclusive em erro ou SIGTERM).
# Uso: desempenho/rodar-benchmark.sh   (a partir da raiz do kit; rode desacoplado com setsid nohup)
set -u
KIT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$KIT/desempenho"
cd "$KIT"
mvn -o -q test-compile dependency:build-classpath -Dmdep.outputFile=target/jmh-classpath.txt -Dmdep.includeScope=test
CP="target/test-classes:target/classes:$(cat target/jmh-classpath.txt)"
OLLAMA=engineering-rag-ollama
religar() { docker start "$OLLAMA" >/dev/null 2>&1 && echo "$(date +%T) ollama religado" >> "$OUT/execucao.log"; }
trap religar EXIT
trap 'exit 143' TERM INT HUP
docker stop "$OLLAMA" >/dev/null 2>&1 && echo "$(date +%T) ollama parado" >> "$OUT/execucao.log"
sleep 20
{
  echo "Commit: $(git rev-parse HEAD)"
  echo "Arvore: $([ -z "$(git status --porcelain -- . ':(exclude)desempenho')" ] && echo limpa || echo 'com alteracoes')"
  echo "Inicio: $(date -Iseconds)"
  echo "Carga media no inicio (1/5/15 min): $(cut -d' ' -f1-3 /proc/loadavg)"
  java -version 2>&1 | head -2
  echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2) ($(nproc) threads logicas)"
  echo "Memoria: $(free -g | awk '/Mem/{print $2}') GiB"
  echo "SO: $(uname -sr)"
  echo "Bouncy Castle: 1.84"
  echo "JMH: 1.36; modo AverageTime; 5 aquecimentos x 1 s; 5 medicoes x 2 s; 5 forks; -Xms512m -Xmx1024m; mensagem assinada varia a cada operacao"
  echo "Conteiner Ollama parado durante a medicao"
} > "$OUT/ambiente.txt"
( while sleep 30; do echo "$(date +%T) $(cut -d' ' -f1-3 /proc/loadavg)"; done ) > "$OUT/carga.log" &
MON=$!
java -cp "$CP" org.openjdk.jmh.Main HybridOperationsBenchmark -rf json -rff "$OUT/resultados.json" > "$OUT/saida-jmh.txt" 2>&1
RC=$?
kill $MON 2>/dev/null
{ echo "Fim: $(date -Iseconds)"; echo "Carga media no fim (1/5/15 min): $(cut -d' ' -f1-3 /proc/loadavg)"; echo "Codigo de saida do JMH: $RC"; } >> "$OUT/ambiente.txt"
echo "$(date +%T) jmh exit=$RC" >> "$OUT/execucao.log"
