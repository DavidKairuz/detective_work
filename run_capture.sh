#!/bin/bash
# ==============================================
# Script: run_capture.sh
# Autor: David Elias Kairuz (adaptado por GPT-5)
# Descripción:
#   Automatiza la ejecución del entorno de prueba
#   con tráfico TCP/UDP, tcpdump y ptcpdump.
# ==============================================

# Configuración
CAPTURE_DIR="./captures"
CAPTURE_TIME=${1:-60}   # segundos (puede pasarse como argumento)
COMPOSE_FILE="docker-compose.yml"

echo "🚀 Iniciando captura de tráfico (duración: ${CAPTURE_TIME}s)..."

# 1. Limpiar capturas previas
# Reemplaza la sección de limpieza de capturas por esto:
echo -e "${BLUE}📁 Preparando directorio de capturas...${NC}"
rm -rf "$CAPTURE_DIR"
mkdir -p "$CAPTURE_DIR"
if groups | grep -q docker; then
    chown $USER:docker "$CAPTURE_DIR"
else
    echo -e "${RED}⚠️  Advertencia: Usuario no está en el grupo docker${NC}"
    echo -e "${BLUE}ℹ️  Configurando permisos alternativos...${NC}"
fi
chmod 775 "$CAPTURE_DIR"

# 2. Construir y levantar contenedores
echo "🐳 Levantando contenedores..."
docker compose -f "$COMPOSE_FILE" up --build -d
# Añadir después de levantar los contenedores:
echo -e "${BLUE}🔍 Verificando estado de contenedores...${NC}"
if ! docker compose -f "$COMPOSE_FILE" ps | grep -q "running"; then
    echo -e "${RED}❌ Error: Los contenedores no están ejecutándose${NC}"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
fi

# 3. Esperar mientras se genera tráfico
echo "⏱️ Esperando ${CAPTURE_TIME}s mientras se genera tráfico..."
sleep "$CAPTURE_TIME"

# 4. Detener contenedores
echo "🛑 Deteniendo contenedores..."
docker compose -f "$COMPOSE_FILE" down

# 5. Mostrar resumen de archivos capturados
echo "📂 Archivos capturados:"
ls -lh "$CAPTURE_DIR" || echo "❌ No se encontraron capturas."

# 6. Mensaje final
echo "✅ Captura completada. Archivos disponibles en: ${CAPTURE_DIR}/"
echo "   - ptcpdump_capture.pcap"
echo "   - tcpdump_capture.pcap"
echo ""
echo "💡 Abrilos con Wireshark o tshark para comparar resultados."
