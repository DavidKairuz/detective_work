#!/usr/bin/env bash

# Colecta métricas por contenedor (aprox por proceso) durante N segundos
# Uso: ./scripts/collect_metrics.sh <duration_seconds> [output_dir]
set -euo pipefail

DURATION=${1:-60}
OUT_DIR=${2:-"./captures"}
mkdir -p "$OUT_DIR"

TCP_CNAME="tcpdump-sniffer"
PTCP_CNAME="ptcpdump-sniffer"
TCP_CSV="$OUT_DIR/tcpdump_container_stats.csv"
PTCP_CSV="$OUT_DIR/ptcpdump_container_stats.csv"

collect_one() {
  local cname="$1"; local outfile="$2"; local dur="$3"
  echo "time_s,cpu_perc,mem_usage,mem_perc" > "$outfile"
  local end=$((SECONDS+dur))
  local t=0
  while [ $SECONDS -lt $end ]; do
    # --no-stream para una muestra puntual
    # Ejemplo de salida: 1.23%,10.2MiB / 11.0GiB,0.09%
    local line
    line=$(docker stats --no-stream --format "{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}}" "$cname" 2>/dev/null || true)
    if [ -n "$line" ]; then
      echo "$t,$line" >> "$outfile"
    fi
    sleep 1
    t=$((t+1))
  done
}

# Correr ambos en paralelo y esperar
collect_one "$TCP_CNAME" "$TCP_CSV" "$DURATION" &
PID1=$!
collect_one "$PTCP_CNAME" "$PTCP_CSV" "$DURATION" &
PID2=$!
wait $PID1 $PID2 || true

exit 0
