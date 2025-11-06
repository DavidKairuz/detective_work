#!/bin/bash
# ==============================================
# Script: run_capture.sh (Versión Simplificada)
# Descripción: Ejecuta capturas con tcpdump y ptcpdump
# ==============================================

# Colores para mejor legibilidad
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

# Configuración básica
CAPTURE_DIR="./captures"
CAPTURE_TIME=${1:-60}
COMPOSE_FILE="docker-compose.yml"

echo -e "${BLUE}🚀 Iniciando entorno con captura real (duración: ${CAPTURE_TIME}s)...${NC}"

# 1. Preparar directorio con permisos correctos
echo -e "${BLUE}📁 Preparando directorio...${NC}"
sudo rm -rf "$CAPTURE_DIR"
sudo mkdir -p "$CAPTURE_DIR"
sudo chmod 777 "$CAPTURE_DIR"

# 2. Levantar contenedores
echo -e "${BLUE}🐳 Iniciando contenedores...${NC}"
# Asegurar que la red externa exista (como la espera docker-compose.yml)
if ! docker network inspect ptcp_docker_net-test >/dev/null 2>&1; then
    echo -e "${BLUE}🌐 Creando red externa ptcp_docker_net-test...${NC}"
    docker network create --driver bridge --subnet 172.18.0.0/16 ptcp_docker_net-test >/dev/null 2>&1 || true
fi
docker compose -f "$COMPOSE_FILE" up -d
sleep 2  # Esperar a que los contenedores estén listos

# 3. Verificar que los contenedores sniffer están activos
if ! docker ps | grep -q "tcpdump-sniffer" || ! docker ps | grep -q "ptcpdump-sniffer"; then
    echo -e "${RED}❌ Error: Uno o ambos contenedores sniffer no están activos${NC}"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
fi
echo -e "${GREEN}✅ Contenedores activos.${NC}"

# 4. Capturas gestionadas por docker-compose (evitar duplicación)
echo -e "${BLUE}📷 Las capturas ya están iniciadas por docker-compose (comandos parametrizados en .env).${NC}"
echo -e "${GREEN}✅ Servicios sniffer corriendo con: TCPDUMP_CMD y PTCPDUMP_CMD.${NC}"

# Asegurar que los archivos de captura estén siendo escritos
echo -e "${BLUE}⏳ Esperando a que las capturas inicien...${NC}"
for i in {1..10}; do
    if [ -f "$CAPTURE_DIR/tcpdump_capture.pcap" ] && [ -f "$CAPTURE_DIR/ptcpdump_capture.pcap" ]; then
        break
    fi
    sleep 0.5
done

# 4.1. Recolección de métricas por contenedor (docker stats) en segundo plano
if [ ! -d "./scripts" ]; then mkdir -p ./scripts; fi
if [ ! -x "./scripts/collect_metrics.sh" ] && [ -f "./scripts/collect_metrics.sh" ]; then chmod +x ./scripts/collect_metrics.sh; fi
if [ -x "./scripts/collect_metrics.sh" ]; then
    echo -e "${BLUE}📊 Iniciando recolección de métricas por contenedor...${NC}"
    ./scripts/collect_metrics.sh "$CAPTURE_TIME" "$CAPTURE_DIR" >/dev/null 2>&1 &
else
    echo -e "ℹ️  No se encontró scripts/collect_metrics.sh; omitiendo métricas por contenedor."
fi

# 5. Iniciar monitoreo de CPU/memoria (si 'sar' está disponible)
if command -v sar >/dev/null 2>&1; then
    echo -e "${BLUE}📊 Registrando métricas de CPU y memoria durante ${CAPTURE_TIME}s...${NC}"
    sar -u 1 ${CAPTURE_TIME} > ${CAPTURE_DIR}/cpu_usage.txt &
    CPU_SAR_PID=$!
    sar -r 1 ${CAPTURE_TIME} > ${CAPTURE_DIR}/mem_usage.txt &
    MEM_SAR_PID=$!
else
    echo -e "⚠️  'sar' no está disponible. Instala 'sysstat' para habilitar métricas (sudo apt-get install -y sysstat)."
fi

# 5. Esperar el tiempo exacto especificado
date +%s.%N > "$CAPTURE_DIR/capture_start_time"
echo -e "${BLUE}⏱️ Iniciando captura de ${CAPTURE_TIME}s...${NC}"

# Esperar el tiempo exacto usando un bucle de control
SECONDS=0
while [ $SECONDS -lt $CAPTURE_TIME ]; do
    REMAINING=$((CAPTURE_TIME - SECONDS))
    echo -ne "\r${BLUE}⏱️ Capturando... ${REMAINING}s restantes${NC}"
    sleep 1
done
echo  # Nueva línea después del contador

# Registrar tiempo final exacto
date +%s.%N > "$CAPTURE_DIR/capture_end_time"

# 6. Detener capturas con parada limpia (flush de .pcap)
echo -e "${BLUE}🛑 Finalizando capturas (stop con gracia)...${NC}"
docker compose -f "$COMPOSE_FILE" stop -t 3
sleep 1

# 7. Finalizar métricas si siguen activas
if [ -n "${CPU_SAR_PID:-}" ]; then kill ${CPU_SAR_PID} 2>/dev/null || true; fi
if [ -n "${MEM_SAR_PID:-}" ]; then kill ${MEM_SAR_PID} 2>/dev/null || true; fi

# 8. Remover contenedores
echo -e "${BLUE}📦 Removiendo contenedores...${NC}"
docker compose -f "$COMPOSE_FILE" down

# 9. Verificar resultados
echo -e "${BLUE}🔍 Verificando capturas:${NC}"
if [ -f "$CAPTURE_DIR/tcpdump_capture.pcap" ] && [ -f "$CAPTURE_DIR/ptcpdump_capture.pcap" ]; then
    echo -e "${GREEN}✅ Capturas completadas exitosamente:${NC}"
    ls -lh "$CAPTURE_DIR"/*.pcap
else
    echo -e "${RED}❌ Error: No se encontraron algunas capturas${NC}"
    ls -l "$CAPTURE_DIR" || true
fi

echo -e "\n💾 Las capturas están en: ${CAPTURE_DIR}/"
echo -e "   Puedes analizarlas con: wireshark $CAPTURE_DIR/*.pcap"

# 10. Ejecutar analizador integrado (tshark + métricas) si está disponible
PY_ANALYZER="analyze_integrated_results.py"
if [ -f "$PY_ANALYZER" ]; then
    echo "\n🔎 Ejecutando analizador (tshark + gráficos)..."
    if command -v python3 >/dev/null 2>&1; then
        python3 "$PY_ANALYZER" || echo "⚠️  El analizador terminó con error, revisa dependencias (pandas/matplotlib/tshark) y archivos en ${CAPTURE_DIR}."
    else
        echo "⚠️  Python 3 no encontrado; omitiendo análisis automático."
    fi
else
    echo "ℹ️  Analizador no encontrado (${PY_ANALYZER})."
fi