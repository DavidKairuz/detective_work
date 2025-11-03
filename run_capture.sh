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
PROFILE_FILE="${2:-}"

# Si se pasa un archivo de perfil (.env), úsalo para parametrizar comandos de sniffers
declare -a COMPOSE_ENV_ARGS=()
if [ -n "$PROFILE_FILE" ]; then
    ENV_PATH="$PROFILE_FILE"
    # Resolver rutas comunes si se pasó solo el nombre
    if [ ! -f "$ENV_PATH" ]; then
        [ -f "./config/${PROFILE_FILE}" ] && ENV_PATH="./config/${PROFILE_FILE}"
    fi
    if [ ! -f "$ENV_PATH" ]; then
        BASE_NOEXT="${PROFILE_FILE%.env}"
        [ -f "./config/${BASE_NOEXT}.env" ] && ENV_PATH="./config/${BASE_NOEXT}.env"
    fi
    if [ ! -f "$ENV_PATH" ]; then
        BASE_NOEXT="${PROFILE_FILE%.env}"
        [ -f "./${BASE_NOEXT}.env" ] && ENV_PATH="./${BASE_NOEXT}.env"
    fi

    if [ -f "$ENV_PATH" ]; then
        echo -e "${BLUE}🧩 Usando perfil de entorno:${NC} ${ENV_PATH}"
        COMPOSE_ENV_ARGS+=("--env-file" "$ENV_PATH")
    else
        echo -e "${RED}❌ Perfil especificado no encontrado:${NC} '${PROFILE_FILE}'." >&2
        echo -e "Sugerencias:" >&2
        echo -e " - Coloca el archivo en ./config/${PROFILE_FILE} o ./config/${PROFILE_FILE%.env}.env" >&2
        echo -e " - O pásalo con ruta completa (p.ej., /ruta/a/${PROFILE_FILE})" >&2
        exit 2
    fi
fi

echo -e "${BLUE}🚀 Iniciando entorno con captura real (duración: ${CAPTURE_TIME}s)...${NC}"

# Mostrar comandos efectivos de captura para trazabilidad
PRINT_ENV_PATH=""
if [ ${#COMPOSE_ENV_ARGS[@]} -gt 0 ]; then
    # Cuando se pasa --env-file, el path está en el último argumento
    PRINT_ENV_PATH="${COMPOSE_ENV_ARGS[${#COMPOSE_ENV_ARGS[@]}-1]}"
elif [ -f "./.env" ]; then
    PRINT_ENV_PATH="./.env"
fi
if [ -n "$PRINT_ENV_PATH" ] && [ -f "$PRINT_ENV_PATH" ]; then
    echo -e "${BLUE}🧪 Comandos efectivos desde:${NC} $PRINT_ENV_PATH"
    TCP_CMD_LINE=$(grep -E '^TCPDUMP_CMD=' "$PRINT_ENV_PATH" | sed 's/^TCPDUMP_CMD=//')
    PTCP_CMD_LINE=$(grep -E '^PTCPDUMP_CMD=' "$PRINT_ENV_PATH" | sed 's/^PTCPDUMP_CMD=//')
    [ -n "$TCP_CMD_LINE" ] && echo -e "  TCPDUMP_CMD=\n    $TCP_CMD_LINE"
    [ -n "$PTCP_CMD_LINE" ] && echo -e "  PTCPDUMP_CMD=\n    $PTCP_CMD_LINE"
fi

# 1. Preparar directorio con permisos correctos
echo -e "${BLUE}📁 Preparando directorio...${NC}"
sudo rm -rf "$CAPTURE_DIR"
sudo mkdir -p "$CAPTURE_DIR"
sudo chmod 777 "$CAPTURE_DIR"

# 2. Levantar contenedores
echo -e "${BLUE}🐳 Iniciando contenedores...${NC}"
docker compose -f "$COMPOSE_FILE" "${COMPOSE_ENV_ARGS[@]}" up -d
sleep 5  # Esperar a que los contenedores estén listos

# 3. Verificar que los contenedores sniffer están activos
if ! docker ps | grep -q "tcpdump-sniffer" || ! docker ps | grep -q "ptcpdump-sniffer"; then
    echo -e "${RED}❌ Error: Uno o ambos contenedores sniffer no están activos${NC}"
    docker compose -f "$COMPOSE_FILE" "${COMPOSE_ENV_ARGS[@]}" logs
    exit 1
fi
echo -e "${GREEN}✅ Contenedores activos.${NC}"

# 4. Capturas gestionadas por docker-compose (evitar duplicación)
echo -e "${BLUE}📷 Las capturas ya están iniciadas por docker-compose (comandos parametrizados en .env).${NC}"
echo -e "${GREEN}✅ Servicios sniffer corriendo con: TCPDUMP_CMD y PTCPDUMP_CMD.${NC}"

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

# 5. Esperar el tiempo especificado
echo -e "${BLUE}⏱️ Capturando durante ${CAPTURE_TIME}s...${NC}"
sleep "$CAPTURE_TIME"

# 6. Detener capturas con parada limpia (flush de .pcap)
echo -e "${BLUE}🛑 Finalizando capturas (stop con gracia)...${NC}"
docker compose -f "$COMPOSE_FILE" "${COMPOSE_ENV_ARGS[@]}" stop -t 5
sleep 2

# 7. Finalizar métricas si siguen activas
if [ -n "${CPU_SAR_PID:-}" ]; then kill ${CPU_SAR_PID} 2>/dev/null || true; fi
if [ -n "${MEM_SAR_PID:-}" ]; then kill ${MEM_SAR_PID} 2>/dev/null || true; fi

# 8. Remover contenedores
echo -e "${BLUE}📦 Removiendo contenedores...${NC}"
docker compose -f "$COMPOSE_FILE" "${COMPOSE_ENV_ARGS[@]}" down

# 9. Verificar resultados
echo -e "${BLUE}🔍 Verificando capturas:${NC}"
if [ -f "$CAPTURE_DIR/tcpdump_capture.pcap" ] && [ -f "$CAPTURE_DIR/ptcpdump_capture.pcap" ]; then
    echo -e "${GREEN}✅ Capturas completadas exitosamente:${NC}"
    ls -lh "$CAPTURE_DIR"/*.pcap
elif [ -f "$CAPTURE_DIR/tcpdump_capture.pcapng" ] && [ -f "$CAPTURE_DIR/ptcpdump_capture.pcapng" ]; then
    echo -e "${GREEN}✅ Capturas (.pcapng) completadas exitosamente:${NC}"
    ls -lh "$CAPTURE_DIR"/*.pcapng
else
    echo -e "${RED}❌ Error: No se encontraron algunas capturas${NC}"
    ls -l "$CAPTURE_DIR" || true
fi

echo -e "\n💾 Las capturas están en: ${CAPTURE_DIR}/"
echo -e "   Puedes analizarlas con: wireshark $CAPTURE_DIR/*.pcap o *.pcapng"