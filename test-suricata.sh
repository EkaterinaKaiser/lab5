#!/bin/bash
set -e

echo "===== Проверка работы Suricata IPS ====="
echo ""

# Ожидание готовности контейнеров
echo "Ожидание готовности контейнеров..."
sleep 10
for i in {1..30}; do
  if docker exec attacker ping -c 1 -W 1 victim >/dev/null 2>&1 || docker exec attacker curl -s http://victim >/dev/null 2>&1; then
    echo "Контейнеры готовы"
    break
  fi
  echo "Ожидание... ($i/30)"
  sleep 2
done

echo ""
echo "===== Тест 1: Ping victim из attacker (ожидаем, что ICMP будет блокироваться Suricata) ====="
echo "Выполняю ping..."
if docker exec attacker ping -c 4 -W 2 victim 2>&1; then
  echo "⚠️  ВНИМАНИЕ: Ping прошел успешно, но должен был быть заблокирован!"
else
  echo "✓ Ping заблокирован (ожидаемое поведение)"
fi

echo ""
echo "===== Тест 2: HTTP-запрос с attacker на victim (ожидаем 200 OK) ====="
echo "Выполняю HTTP-запрос..."
HTTP_CODE=$(docker exec attacker curl -s -o /dev/null -w "%{http_code}" http://victim || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ HTTP запрос успешен (HTTP code: $HTTP_CODE)"
else
  echo "⚠️  HTTP запрос не выполнен или вернул код: $HTTP_CODE"
fi

echo ""
echo "===== Тест 3: Проверка логов Suricata (eve.json) ====="
echo "Последние события Suricata из eve.json:"
if command -v jq >/dev/null 2>&1; then
  if [ -f /var/log/suricata/eve.json ]; then
    echo "Последние 20 событий:"
    sudo tail -n 20 /var/log/suricata/eve.json | jq '.' 2>/dev/null || sudo tail -n 20 /var/log/suricata/eve.json
    echo ""
    echo "Проверка событий drop (ICMP блокировка):"
    DROP_COUNT=$(sudo tail -n 50 /var/log/suricata/eve.json | jq -r 'select(.event_type=="drop") | .event_type' 2>/dev/null | wc -l)
    if [ "$DROP_COUNT" -gt 0 ]; then
      echo "✓ Найдено событий drop: $DROP_COUNT"
      echo "Примеры событий drop:"
      sudo tail -n 50 /var/log/suricata/eve.json | jq 'select(.event_type=="drop")' 2>/dev/null | head -n 20
    else
      echo "⚠️  События drop не найдены в последних 50 записях"
    fi
    echo ""
    echo "Проверка HTTP событий:"
    HTTP_COUNT=$(sudo tail -n 50 /var/log/suricata/eve.json | jq -r 'select(.event_type=="http") | .event_type' 2>/dev/null | wc -l)
    if [ "$HTTP_COUNT" -gt 0 ]; then
      echo "✓ Найдено HTTP событий: $HTTP_COUNT"
      echo "Примеры HTTP событий:"
      sudo tail -n 50 /var/log/suricata/eve.json | jq 'select(.event_type=="http")' 2>/dev/null | head -n 20
    else
      echo "⚠️  HTTP события не найдены в последних 50 записях"
    fi
  else
    echo "⚠️  Файл /var/log/suricata/eve.json не найден"
  fi
else
  echo "jq не установлен, показываю последние 30 строк лога:"
  sudo tail -n 30 /var/log/suricata/eve.json 2>/dev/null || echo "Лог недоступен"
fi

echo ""
echo "===== Проверка статуса Suricata ====="
if systemctl is-active --quiet suricata; then
  echo "✓ Suricata работает"
else
  echo "⚠️  Suricata не работает"
  systemctl status suricata --no-pager || true
fi

echo ""
echo "===== Проверка правил iptables ====="
echo "Правила NFQUEUE:"
sudo iptables -L FORWARD -n -v | grep NFQUEUE || echo "Правила NFQUEUE в FORWARD не найдены"
sudo iptables -L DOCKER-USER -n -v 2>/dev/null | grep NFQUEUE || echo "Правила NFQUEUE в DOCKER-USER не найдены"

echo ""
echo "===== Проверка завершена ====="
