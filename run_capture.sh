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
echo "🧹 Limpiando capturas anteriores..."
rm -rf "$CAPTURE_DIR"
mkdir -p "$CAPTURE_DIR"

# 2. Construir y levantar contenedores
echo "🐳 Levantando contenedores..."
docker compose -f "$COMPOSE_FILE" up --build -d

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
