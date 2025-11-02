#!/usr/bin/env python3
# ==============================================
# Script: analyze_integrated_results.py
# Descripción:
#   Analiza las métricas de rendimiento del host (CPU, Memoria) 
#   y las métricas de tráfico de red (Paquetes, Bytes, Tamaño de archivo)
#   para comparar la eficiencia y la carga de datos entre ptcpdump y tcpdump.
# ==============================================

import os
import pandas as pd
import matplotlib.pyplot as plt
import subprocess
import sys
import re

# Rutas de los archivos generados por la captura
CAPTURE_DIR = "./captures"
CPU_FILE = os.path.join(CAPTURE_DIR, "cpu_usage.txt")
MEM_FILE = os.path.join(CAPTURE_DIR, "mem_usage.txt")
PCAP_TCPDUMP = os.path.join(CAPTURE_DIR, "tcpdump_capture.pcap")
PCAP_PTCPDUMP = os.path.join(CAPTURE_DIR, "ptcpdump_capture.pcap")

print("🔍 Iniciando análisis de métricas integradas...")

# =====================================
# Función de verificación
# =====================================
def check_prerequisites():
    """Verifica la existencia de archivos y la herramienta tshark."""
    required_files = [CPU_FILE, MEM_FILE, PCAP_TCPDUMP, PCAP_PTCPDUMP]
    
    # 1. Verificar archivos
    for file in required_files:
        if not os.path.exists(file):
            print(f"❌ Error: No se encontró el archivo requerido: {file}")
            sys.exit(1)

    # 2. Verificar tshark
    try:
        subprocess.run("tshark -v", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("❌ Error: 'tshark' no está instalado o no está en el PATH.")
        sys.exit(1)
    
    print("✅ Archivos y prerrequisitos verificados.")

# =====================================
# 1. Análisis de uso de CPU y Memoria
# =====================================
def analyze_system_metrics():
    """Procesa los archivos de CPU y Memoria."""
    cpu_data, mem_data = pd.DataFrame(), pd.DataFrame()
    cpu_mean, mem_mean = pd.Series(dtype=float), pd.Series(dtype=float)

    # CPU
    try:
        print("📊 Procesando métricas de CPU...")
        with open(CPU_FILE, 'r') as f:
            lines = f.readlines()
        data_lines = [line.replace(',', '.') for line in lines[3:] if 'all' in line]
        
        cpu_data = pd.DataFrame([
            line.split()[2:6] for line in data_lines
        ], columns=["user", "nice", "system", "idle"]).astype(float)
        cpu_mean = cpu_data.mean()
        cpu_data["time"] = range(1, len(cpu_data) + 1)
    except Exception as e:
        print(f"⚠️ Advertencia: No se pudo analizar el archivo de CPU: {e}")

    # Memoria
    try:
        print("📊 Procesando métricas de memoria...")
        with open(MEM_FILE, 'r') as f:
            lines = f.readlines()
        data_lines = []
        for line in lines[3:]:
            if len(line.split()) >= 6:
                processed_line = line.replace(',', '.')
                data_lines.append(processed_line)
        
        # Campos esperados tras la hora: [kbmemfree, kbavail, kbmemused, %memused, kbbuffers, kbcached, ...]
        # Seleccionamos índices [1,3,4,5,6] => kbmemfree, kbmemused, %memused, kbbuffers, kbcached
        mem_data = pd.DataFrame([
            [vals[1], vals[3], vals[4], vals[5], vals[6]]
            for vals in (line.split() for line in data_lines)
            if len(vals) >= 7
        ], columns=["kbmemfree", "kbmemused", "%memused", "kbbuffers", "kbcached"]).astype(float)
        mem_mean = mem_data.mean()
        mem_data["time"] = range(1, len(mem_data) + 1)
    except Exception as e:
        print(f"⚠️ Advertencia: No se pudo analizar el archivo de memoria: {e}")
        
    return cpu_data, mem_data, cpu_mean, mem_mean

# =====================================
# 2. Análisis de Tráfico (TShark) - FUNCIÓN CORREGIDA
# =====================================
def get_tshark_stats(pcap_file):
    """
    Ejecuta tshark -qz io,phs y parsea el resultado buscando los totales
    de 'frames' y 'bytes' en la sección de Protocol Hierarchy (eth o sll).
    """
    print(f"📦 Analizando tráfico con TShark: {pcap_file}...")
    try:
        # Usamos io,phs, aunque solo usaremos la parte de Protocol Hierarchy
        command = f"tshark -r {pcap_file} -qz io,phs"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        
        stats = {"packets": 0, "bytes": 0}

        # Buscar la primera línea de la jerarquía (eth o sll) y extraer frames/bytes
        pattern = re.compile(r"^(eth|sll)\s+.*?frames:(\d+)\s+bytes:(\d+)")
        for raw in result.stdout.splitlines():
            line = raw.strip()
            m = pattern.match(line)
            if m:
                stats["packets"] = int(m.group(2))
                stats["bytes"] = int(m.group(3))
                break

        return stats
    except subprocess.CalledProcessError as e:
        print(f"❌ Error al ejecutar TShark. Revise el archivo. Error: {e.stderr.strip()}")
        return {"packets": 0, "bytes": 0}
    except Exception as e:
        print(f"⚠️ Error desconocido al procesar TShark: {e}")
        return {"packets": 0, "bytes": 0}

# =====================================
# Función Principal de Ejecución
# =====================================
def main():
    check_prerequisites()
    
    # 1. Métricas de Sistema
    cpu_data, mem_data, cpu_mean, mem_mean = analyze_system_metrics()

    # 2. Métricas de Tráfico
    tshark_tcpdump = get_tshark_stats(PCAP_TCPDUMP)
    tshark_ptcpdump = get_tshark_stats(PCAP_PTCPDUMP)
    
    # 3. Tamaños de archivo
    size_tcpdump = os.path.getsize(PCAP_TCPDUMP)
    size_ptcpdump = os.path.getsize(PCAP_PTCPDUMP)

    # 4. Consolidación y Visualización de Resultados
    print("\n===== RESULTADOS INTEGRADOS Y COMPARATIVOS =====")

    # --- Tabla de Métricas de Tráfico y Metadatos ---
    print("\n📊 4.1. Comparativa de Tráfico Capturado y Carga (Metadatos):")
    traffic_data = {
        "Herramienta": ["tcpdump", "ptcpdump"],
        "Paquetes Total": [tshark_tcpdump['packets'], tshark_ptcpdump['packets']],
        "Bytes Netos (Payload)": [tshark_tcpdump['bytes'], tshark_ptcpdump['bytes']],
        "Tamaño Archivo (KB)": [size_tcpdump / 1024, size_ptcpdump / 1024]
    }
    traffic_df = pd.DataFrame(traffic_data)
    print(traffic_df.to_string(index=False, float_format="%.2f"))

    # Conclusión sobre metadatos
    if tshark_ptcpdump['packets'] > 0:
        if tshark_ptcpdump['packets'] == tshark_tcpdump['packets']:
            if size_ptcpdump > size_tcpdump:
                diff_kb = (size_ptcpdump - size_tcpdump) / 1024
                print(f"\n📢 Conclusión de Archivos:")
                print(f"   Ambas capturas tienen el mismo número de paquetes. La diferencia de {diff_kb:.2f} KB en ptcpdump confirma la **inclusión de metadatos de Contenedor/Proceso** (eBPF).")
            else:
                print("\n📢 Conclusión de Archivos:")
                print("   Ambas capturas tienen el mismo número de paquetes, pero ptcpdump es más pequeño/similar, lo que puede deberse a la eficiencia del formato .pcapng.")
        else:
             print("\n⚠️ ALERTA: Diferencia en el conteo de paquetes. ptcpdump tiene capacidad para capturar paquetes que tcpdump podría perder en interfaces virtuales.")
    else:
        print("\n⚠️ ALERTA: No se detectaron paquetes de red en la captura. Revise la ejecución de Docker Compose o los comandos de captura.")


    # --- Promedio de Uso de Recursos ---
    print("\n📊 4.2. Promedio de Uso de Recursos del Host (Overhead):")
    if not cpu_mean.empty:
        print("\n   - Uso de CPU (%):")
        print(cpu_mean[["user", "system"]].round(2).to_string())
    
    if not mem_mean.empty:
        # Derivar promedios en MB a partir de KB
        mem_total_avg_kb = (mem_mean.get("kbmemfree", 0.0) + mem_mean.get("kbmemused", 0.0))
        mem_used_avg_mb = mem_mean.get("kbmemused", 0.0) / 1024.0
        mem_total_avg_mb = mem_total_avg_kb / 1024.0 if mem_total_avg_kb else 0.0

        print("\n   - Uso de Memoria:")
        print(f"     %memused (promedio): {mem_mean.get('%memused', 0.0):.2f} %")
        print(f"     Mem usada (promedio): {mem_used_avg_mb:.2f} MB de {mem_total_avg_mb:.2f} MB")


    # --- Visualización de resultados ---
    # Comparación de tamaños de archivos
    plt.figure(figsize=(6, 4))
    plt.bar(["tcpdump", "ptcpdump"], traffic_df["Tamaño Archivo (KB)"], color=["gray", "blue"])
    plt.ylabel("Tamaño (KB)")
    plt.title("Comparativa de Tamaño de Archivos de Captura")
    plt.tight_layout()
    plt.savefig(os.path.join(CAPTURE_DIR, "pcap_size_comparison.png"))
    plt.close()

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

    # --- Exportar resumen ---
    results_summary = {
        "metric": ["tcpdump", "ptcpdump"],
        "packets_total": [tshark_tcpdump['packets'], tshark_ptcpdump['packets']],
        "bytes_netos": [tshark_tcpdump['bytes'], tshark_ptcpdump['bytes']],
        "pcap_size_kb": [size_tcpdump / 1024, size_ptcpdump / 1024]
    }
    df_summary = pd.DataFrame(results_summary)
    
    df_summary["cpu_user_avg"] = [cpu_mean.get("user", 0)] * 2
    df_summary["cpu_system_avg"] = [cpu_mean.get("system", 0)] * 2
    df_summary["mem_used_pct_avg"] = [mem_mean.get("%memused", 0.0)] * 2
    # Añadir métricas de memoria en MB para claridad
    mem_total_avg_kb = (mem_mean.get("kbmemfree", 0.0) + mem_mean.get("kbmemused", 0.0)) if not mem_mean.empty else 0.0
    df_summary["mem_used_mb_avg"] = [mem_mean.get("kbmemused", 0.0) / 1024.0] * 2
    df_summary["mem_total_mb_avg"] = [(mem_total_avg_kb / 1024.0) if mem_total_avg_kb else 0.0] * 2
    
    df_summary.to_csv(os.path.join(CAPTURE_DIR, "results_summary.csv"), index=False, float_format="%.2f")

    print("\n📁 Resultados finales exportados en el directorio 'captures/'.")
    print("✅ Análisis completado correctamente.")

if __name__ == "__main__":
    main()