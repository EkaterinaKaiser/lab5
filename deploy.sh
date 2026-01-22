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

# Копирование suricata.yaml (должен быть скопирован из проекта)
if [ ! -f /tmp/suricata.yaml ]; then
    echo "Ошибка: файл /tmp/suricata.yaml не найден"
    exit 1
fi
sudo cp /tmp/suricata.yaml /etc/suricata/suricata.yaml

# Создание правил Suricata
cat > /etc/suricata/rules/local.rules <<'EORULES'
drop icmp any any -> any any (msg:"[IPS] BLOCK ICMP"; sid:1000007; rev:1;)

alert http any any -> any any (msg:"[IDS] HTTP Request Detected"; sid:100002; rev:1; flow:to_server; classtype:policy-violation;)
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
