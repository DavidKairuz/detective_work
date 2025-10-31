#!/usr/bin/env python3
# ==============================================
# Script: analyze_integrated_results.py
# Descripción:
#   Analiza las métricas generadas por run_capture.sh
#   (CPU, memoria y tamaño de archivos .pcap)
#   y produce resultados comparativos y gráficos.
# ==============================================

import os
import pandas as pd
import matplotlib.pyplot as plt

# Rutas de los archivos generados por run_capture.sh
CAPTURE_DIR = "./captures"
CPU_FILE = os.path.join(CAPTURE_DIR, "cpu_usage.txt")
MEM_FILE = os.path.join(CAPTURE_DIR, "mem_usage.txt")
PCAP_TCPDUMP = os.path.join(CAPTURE_DIR, "tcpdump_capture.pcap")
PCAP_PTCPDUMP = os.path.join(CAPTURE_DIR, "ptcpdump_capture.pcap")

print("🔍 Iniciando análisis de métricas...")

# Verificar existencia de archivos
required_files = [CPU_FILE, MEM_FILE, PCAP_TCPDUMP, PCAP_PTCPDUMP]
for file in required_files:
    if not os.path.exists(file):
        print(f"❌ Error: No se encontró el archivo requerido: {file}")
        exit(1)

# ==========================
# 1. Análisis de uso de CPU
# ==========================
print("📊 Procesando métricas de CPU...")
try:
    # Leer el archivo y reemplazar comas por puntos
    with open(CPU_FILE, 'r') as f:
        lines = f.readlines()
    
    # Procesar solo las líneas de datos (después del encabezado)
    data_lines = [line.replace(',', '.') for line in lines[3:] if 'all' in line]
    
    # Crear DataFrame con los datos procesados
    cpu_data = pd.DataFrame([
        line.split()[2:6] for line in data_lines
    ], columns=["user", "nice", "system", "idle"]).astype(float)
    
    cpu_mean = cpu_data.mean()
    cpu_data["time"] = range(1, len(cpu_data) + 1)
except Exception as e:
    print(f"⚠️ No se pudo analizar el archivo de CPU: {e}")
    cpu_data = pd.DataFrame()
    cpu_mean = pd.Series(dtype=float)

# ==========================
# 2. Análisis de memoria
# ==========================
print("📊 Procesando métricas de memoria...")
try:
    # Leer el archivo y reemplazar comas por puntos
    with open(MEM_FILE, 'r') as f:
        lines = f.readlines()
    
    # Procesar líneas de datos (después del encabezado)
    data_lines = []
    for line in lines[3:]:
        if len(line.split()) >= 6:  # Asegurarse de que la línea tiene suficientes campos
            # Reemplazar comas por puntos en los valores numéricos
            processed_line = line.replace(',', '.')
            data_lines.append(processed_line)
    
    # Crear DataFrame con los datos procesados
    mem_data = pd.DataFrame([
        line.split()[1:6] for line in data_lines
    ], columns=["kbmemfree", "kbmemused", "%memused", "kbbuffers", "kbcached"]).astype(float)
    
    mem_mean = mem_data.mean()
    mem_data["time"] = range(1, len(mem_data) + 1)
except Exception as e:
    print(f"⚠️ No se pudo analizar el archivo de memoria: {e}")
    mem_data = pd.DataFrame()
    mem_mean = pd.Series(dtype=float)

# =====================================
# 3. Tamaño de archivos de captura .pcap
# =====================================
print("📦 Analizando archivos de captura...")
size_tcpdump = os.path.getsize(PCAP_TCPDUMP)
size_ptcpdump = os.path.getsize(PCAP_PTCPDUMP)

# =====================================
# 4. Mostrar resultados comparativos
# =====================================
print("\n===== RESULTADOS COMPARATIVOS =====")
print(f"Tamaño tcpdump:  {size_tcpdump / 1024:.2f} KB")
print(f"Tamaño ptcpdump: {size_ptcpdump / 1024:.2f} KB")

if size_ptcpdump > size_tcpdump:
    print("✅ Ptcpdump capturó más información útil (mayor carga).")
else:
    print("ℹ️ Tcpdump generó más datos, revisar contenido o ruido.")

print("\n📈 Promedio de uso de CPU:")
print(cpu_mean.round(2))

print("\n📈 Promedio de uso de Memoria:")
print(mem_mean.round(2))

# =====================================
# 5. Visualización de resultados
# =====================================

# CPU usage over time
if not cpu_data.empty:
    plt.figure(figsize=(8, 4))
    plt.plot(cpu_data["time"], cpu_data["user"], label="User", linewidth=1.2)
    plt.plot(cpu_data["time"], cpu_data["system"], label="System", linewidth=1.2)
    plt.xlabel("Tiempo (s)")
    plt.ylabel("Uso de CPU (%)")
    plt.title("Evolución del uso de CPU durante la captura")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(CAPTURE_DIR, "cpu_usage_plot.png"))
    plt.close()

# Memory usage over time
if not mem_data.empty:
    plt.figure(figsize=(8, 4))
    plt.plot(mem_data["time"], mem_data["%memused"], label="% Memoria usada", color="orange", linewidth=1.2)
    plt.xlabel("Tiempo (s)")
    plt.ylabel("Uso de Memoria (%)")
    plt.title("Evolución del uso de memoria durante la captura")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(CAPTURE_DIR, "mem_usage_plot.png"))
    plt.close()

# Comparación de tamaños de archivos
plt.figure(figsize=(5, 4))
plt.bar(["tcpdump", "ptcpdump"], [size_tcpdump / 1024, size_ptcpdump / 1024], color=["gray", "blue"])
plt.ylabel("Tamaño (KB)")
plt.title("Comparativa de tamaño de archivos .pcap")
plt.tight_layout()
plt.savefig(os.path.join(CAPTURE_DIR, "pcap_size_comparison.png"))
plt.close()

# =====================================
# 6. Exportar resultados a CSV
# =====================================
results_summary = {
    "tcpdump_size_kb": [size_tcpdump / 1024],
    "ptcpdump_size_kb": [size_ptcpdump / 1024],
    "cpu_user_avg": [cpu_mean.get("user", 0)],
    "cpu_system_avg": [cpu_mean.get("system", 0)],
    "mem_used_avg": [mem_mean.get("%memused", 0)]
}

df_summary = pd.DataFrame(results_summary)
df_summary.to_csv(os.path.join(CAPTURE_DIR, "results_summary.csv"), index=False)

print("\n📁 Resultados exportados a:")
print(f"   - {CAPTURE_DIR}/results_summary.csv")
print(f"   - {CAPTURE_DIR}/cpu_usage_plot.png")
print(f"   - {CAPTURE_DIR}/mem_usage_plot.png")
print(f"   - {CAPTURE_DIR}/pcap_size_comparison.png")

print("\n✅ Análisis completado correctamente.")
