#!/bin/bash
set -e

echo "Установка Suricata"
sudo apt update
sudo apt install -y suricata

# Копируем конфиг и правила
sudo cp suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo mkdir -p /etc/suricata/rules
sudo cp suricata/rules/local.rules /etc/suricata/rules/

# Настройка iptables для IPS
echo "Настройка iptables для NFQ"
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 || true

# Проверка конфига Suricata
echo "Проверка конфига Suricata"
sudo mkdir -p /tmp/suricata-test
sudo suricata -T -c /etc/suricata/suricata.yaml -l /tmp/suricata-test

# Запуск Suricata
echo "Запуск Suricata в режиме IPS (NFQ)"
if sudo systemctl restart suricata 2>/dev/null; then
  sudo systemctl enable suricata || true
  echo "Suricata запущена как systemd-сервис"
else
  echo "Не удалось запустить Suricata через systemd, запускаю напрямую (daemon)"
  sudo pkill -x suricata || true
  sudo suricata -c /etc/suricata/suricata.yaml -q 0 -D
fi

echo "Suricata IPS настроена."
echo "Правило iptables применено: FORWARD → NFQUEUE (если iptables доступен)"
echo "Логи: sudo tail -f /var/log/suricata/fast.log"