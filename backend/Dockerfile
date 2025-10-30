FROM ubuntu:22.04

RUN apt update && \
    apt install -y busybox-static iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD bash -c "\
  echo '=== Backend escuchando en puertos 5000 (TCP) y 5001 (UDP)' && \
  mkdir -p /logs && \
  (busybox nc -lkp 5000 > /logs/tcp_traffic.log &) && \
  (busybox nc -u -lkp 5001 > /logs/udp_traffic.log &) && \
  tail -f /logs/tcp_traffic.log /logs/udp_traffic.log \
"
