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
docker compose -f "$COMPOSE_FILE" up -d
sleep 5  # Esperar a que los contenedores estén listos

# 3. Verificar que los contenedores sniffer están activos
if ! docker ps | grep -q "tcpdump-sniffer" || ! docker ps | grep -q "ptcpdump-sniffer"; then
    echo -e "${RED}❌ Error: Uno o ambos contenedores sniffer no están activos${NC}"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
fi
echo -e "${GREEN}✅ Contenedores activos.${NC}"

# 4. Iniciar capturas (versión simplificada y probada)
echo -e "${BLUE}📷 Iniciando capturas...${NC}"

# Iniciar tcpdump
docker exec tcpdump-sniffer tcpdump -i any -w /captures/tcpdump_capture.pcap &
sleep 2  # Pequeña pausa entre capturas

# Iniciar ptcpdump
docker exec ptcpdump-sniffer ptcpdump -i any -w /captures/ptcpdump_capture.pcap &
sleep 2  # Asegurar que ambas capturas han iniciado

echo -e "${GREEN}✅ Capturas iniciadas dentro del contenedor 'sniffer'.${NC}"

echo -e "${GREEN}✅ Capturas iniciadas${NC}"

# 5. Esperar el tiempo especificado
echo -e "${BLUE}⏱️ Capturando durante ${CAPTURE_TIME}s...${NC}"
sleep "$CAPTURE_TIME"

# 6. Detener capturas de manera segura
echo -e "${BLUE}🛑 Finalizando capturas...${NC}"
docker exec tcpdump-sniffer killall -2 tcpdump
docker exec ptcpdump-sniffer killall -2 ptcpdump
sleep 2  # Dar tiempo para que las capturas se guarden

# 7. Detener contenedores
echo -e "${BLUE}� Deteniendo contenedores...${NC}"
docker compose -f "$COMPOSE_FILE" down

# 8. Verificar resultados
echo -e "${BLUE}� Verificando capturas:${NC}"
if [ -f "$CAPTURE_DIR/tcpdump_capture.pcap" ] && [ -f "$CAPTURE_DIR/ptcpdump_capture.pcap" ]; then
    echo -e "${GREEN}✅ Capturas completadas exitosamente:${NC}"
    ls -lh "$CAPTURE_DIR"/*.pcap
else
    echo -e "${RED}❌ Error: No se encontraron algunas capturas${NC}"
    ls -l "$CAPTURE_DIR" || true
fi

echo -e "\n💾 Las capturas están en: ${CAPTURE_DIR}/"
echo -e "   Puedes analizarlas con: wireshark $CAPTURE_DIR/*.pcap"