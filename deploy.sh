#!/bin/bash
set -e

# Установка базовых утилит и Docker
sudo apt-get update -qq
sudo apt-get install -y docker.io curl jq iptables-persistent libnetfilter-queue1
sudo systemctl enable --now docker

# Bridge netfilter setup
sudo modprobe br_netfilter
echo "br_netfilter" | sudo tee /etc/modules-load.d/br_netfilter.conf >/dev/null
cat <<'EOT' | sudo tee /etc/sysctl.d/99-bridge-nf.conf >/dev/null
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOT
sudo sysctl -p /etc/sysctl.d/99-bridge-nf.conf

# Установка Suricata
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata

# Создание директории для правил
sudo mkdir -p /etc/suricata/rules
sudo mkdir -p /var/log/suricata

# Копирование suricata.yaml
SURICATA_CONFIG=""
if [ -f suricata/suricata.yaml ]; then
    SURICATA_CONFIG="suricata/suricata.yaml"
elif [ -f suricata.yaml ]; then
    SURICATA_CONFIG="suricata.yaml"
else
    echo "Ошибка: файл suricata.yaml не найден (проверены пути: suricata/suricata.yaml и suricata.yaml)"
    exit 1
fi
sudo cp "$SURICATA_CONFIG" /etc/suricata/suricata.yaml

# Создание правил Suricata
cat > /etc/suricata/rules/local.rules <<'EORULES'
drop icmp any any -> any any (msg:"[IPS] BLOCK ICMP"; sid:1000007; rev:1;)

alert http any any -> any any (msg:"[IDS] HTTP Request Detected"; sid:100002; rev:1; flow:to_server; classtype:policy-violation;)

# Пример сигнатуры scan SYN (nmap -sS)
drop tcp any any -> any any (flags:S; msg:"[IPS] NMAP SYN Scan Blocked"; threshold: type both, track by_src, count 10, seconds 6; sid:1001001; rev:1;)
# Пример детектирования Xmas scan (nmap -sX)
alert tcp any any -> any any (flags:FPU; msg:"[IDS] NMAP XMAS Scan Detected"; threshold: type both, track by_src, count 5, seconds 6; sid:1001002; rev:1;)
# Пример блокировки UDP scan 
drop udp any any -> any any (msg:"[IPS] NMAP UDP Scan Blocked"; threshold: type both, track by_src, count 10, seconds 10; sid:1001003; rev:1;)
# Пример детектирования OS-фингерпринтинга (nmap -O)
alert ip any any -> any any (msg:"[IDS] Possible OS Fingerprinting Attempt"; ipopts: any; threshold: type both, track by_src, count 5, seconds 20; sid:1001101; rev:1;)

# ACK scan (nmap -sA)
alert tcp any any -> any any (flags:A; msg:"[IDS] NMAP ACK Scan Detected"; threshold: type both, track by_src, count 5, seconds 10; sid:1001004; rev:1;)
# Фин-флаг портсканирование (nmap -sF)
alert tcp any any -> any any (flags:F; msg:"[IDS] NMAP FIN Scan Detected"; threshold: type both, track by_src, count 3, seconds 10; sid:1001005; rev:1;)
# Null scan (nmap -sN)
alert tcp any any -> any any (flags:0; msg:"[IDS] NMAP NULL Scan Detected"; threshold: type both, track by_src, count 2, seconds 10; sid:1001006; rev:1;)

EORULES

# NFQUEUE for Docker traffic
sudo iptables -D DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || true
sudo iptables -I DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass
sudo netfilter-persistent save

# Настройка Suricata
setcap cap_net_admin,cap_net_raw+ep /usr/bin/suricata
mkdir -p /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/override.conf <<'EOSERVICE'
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 1 --pidfile /run/suricata.pid
EOSERVICE

# Запуск Suricata
systemctl daemon-reload
systemctl enable suricata
systemctl restart suricata
systemctl status suricata --no-pager

sudo apt-get install curl
curl -fsSL https://evebox.org/files/GPG-KEY-evebox -o /etc/apt/keyrings/evebox.asc
echo "deb [signed-by=/etc/apt/keyrings/evebox.asc] https://evebox.org/files/debian stable main" | sudo tee /etc/apt/sources.list.d/evebox.list
sudo apt-get update
sudo apt-get install evebox

sudo usermod -a -G suricata evebox

# EveBox: читать события напрямую из eve.json (SQLite + файл логов Suricata)
sudo tee /etc/default/evebox > /dev/null <<'EOEVEBOX'
EVEBOX_OPTS="--database sqlite /var/log/suricata/eve.json"
EOEVEBOX

# Права на чтение логов Suricata для пользователя evebox
sudo chown -R root:suricata /var/log/suricata
sudo chmod 750 /var/log/suricata
sudo touch /var/log/suricata/eve.json
sudo chmod 640 /var/log/suricata/eve.json

sudo systemctl daemon-reload
sudo systemctl restart evebox
sudo systemctl enable evebox
