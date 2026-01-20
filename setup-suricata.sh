#!/bin/bash
set -e

echo "Установка Suricata"
sudo apt update
sudo apt install -y suricata

# Копируем конфиг и правила
sudo cp suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo mkdir -p /etc/suricata/rules
sudo cp suricata/rules/local.rules /etc/suricata/rules/

# Создаём директорию для логов
sudo mkdir -p /var/log/suricata

# Загрузка модулей ядра для NFQ
echo "Загрузка модулей ядра для NFQ"
sudo modprobe nfnetlink || true
sudo modprobe nfnetlink_queue || true

# Проверка что модули загружены
echo "Проверка загруженных модулей NFQ:"
if sudo lsmod | grep -q nfnetlink_queue; then
  echo "✓ Модуль nfnetlink_queue загружен"
else
  echo "⚠ Модуль nfnetlink_queue не загружен (возможны проблемы с NFQ)"
fi

# Убиваем все процессы Suricata перед запуском
echo "Остановка существующих процессов Suricata"
sudo pkill -x suricata || true
sudo systemctl stop suricata 2>/dev/null || true
sleep 2

# Очистка старых правил NFQUEUE из iptables
echo "Очистка старых правил NFQUEUE"
while sudo iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null; do
  echo "Удалено старое правило NFQUEUE"
done
sleep 2

# Проверка, не занята ли очередь другим процессом
echo "Проверка занятости NFQ очереди 0:"
if sudo lsof /proc/net/netfilter/nfnetlink_queue 2>/dev/null | grep -q "queue 0"; then
  echo "⚠ Очередь 0 может быть занята другим процессом"
  sudo lsof /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true
fi

# Настройка iptables для IPS (одно правило)
echo "Добавление правила iptables для NFQ"
sudo iptables -I FORWARD 1 -j NFQUEUE --queue-num 0 || true
sleep 2

# Проверка конфига Suricata
echo "Проверка конфига Suricata"
sudo mkdir -p /tmp/suricata-test
sudo suricata -T -c /etc/suricata/suricata.yaml -l /tmp/suricata-test

# Запуск Suricata
echo "Запуск Suricata в режиме IPS (NFQ)"
# Пробуем запустить напрямую в daemon режиме (systemd часто не работает с NFQ)
echo "Запуск Suricata в daemon режиме с NFQ..."

# Сначала пробуем запустить в foreground для проверки ошибок
echo "Тестовый запуск Suricata (5 секунд) для проверки NFQ..."
timeout 5 sudo suricata -c /etc/suricata/suricata.yaml -q 0 -v 2>&1 | grep -E "(nfq|NFQ|queue|error|Error|failed|Failed)" | head -10 || true
sleep 1

# Теперь запускаем в daemon режиме
echo "Запуск Suricata в daemon режиме..."
sudo suricata -c /etc/suricata/suricata.yaml -q 0 -D
sleep 5

# Проверка что Suricata запущена
if pgrep -x suricata > /dev/null; then
  SURICATA_PID=$(pgrep -x suricata)
  echo "✓ Suricata запущена (PID: $SURICATA_PID)"
  # Проверяем, что процесс действительно работает
  if ps -p $SURICATA_PID > /dev/null 2>&1; then
    echo "✓ Процесс Suricata активен"
  else
    echo "⚠ Процесс Suricata не найден"
  fi
else
  echo "⚠ Suricata не запущена"
  echo "Последние ошибки из логов:"
  sudo tail -n 10 /var/log/suricata/eve.json 2>/dev/null | grep -i error || echo "Логи недоступны"
fi

echo ""
echo "Suricata IPS настроена."
echo "Правило iptables применено: FORWARD → NFQUEUE (если iptables доступен)"
echo "Проверка правила iptables:"
sudo iptables -L FORWARD -n -v | grep NFQUEUE || echo "Правило NFQUEUE не найдено в FORWARD"
echo ""
echo "Логи: sudo tail -f /var/log/suricata/fast.log"