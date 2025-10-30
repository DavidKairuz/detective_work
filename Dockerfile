FROM ubuntu:22.04 AS downloader

# Instalar curl para la descarga
RUN apt update && \
    apt install -y curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Descargar y extraer el binario para amd64
RUN curl -L -o ptcpdump.tar.gz https://github.com/mozillazg/ptcpdump/releases/download/v0.35.1/ptcpdump_0.35.1_linux_amd64.tar.gz && \
    tar xzf ptcpdump.tar.gz && \
    chmod +x ptcpdump

# ====== STAGE 2: runtime ======
FROM ubuntu:22.04 AS runtime

# Instalar solo lo necesario para ejecutar
RUN apt update && \
    apt install -y libpcap0.8 libdbus-1-3 ca-certificates --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Copiar el binario descargado
COPY --from=downloader /tmp/ptcpdump /usr/local/bin/ptcpdump

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["ptcpdump --help"]