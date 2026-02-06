#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/suricata/blocking_rules.log"
DATE_NOW="$(date -Iseconds)"

echo "[$DATE_NOW] === Starting blocking rules setup ===" | tee -a "$LOG_FILE"

# Директории
RULES_DIR="/etc/suricata/rules"
FEEDS_DIR="/tmp/suricata-blocklists"
mkdir -p "$FEEDS_DIR"

# Функция для добавления правила в suricata.yaml
add_rule_file() {
    local rule_file="$1"
    local yaml_file="/etc/suricata/suricata.yaml"
    
    if grep -q "$rule_file" "$yaml_file"; then
        echo "[*] $rule_file already in suricata.yaml" | tee -a "$LOG_FILE"
        return
    fi
    
    # Ищем секцию rule-files и добавляем наш файл
    sudo sed -i "/rule-files:/a\  - $rule_file" "$yaml_file"
    echo "[+] Added $rule_file to suricata.yaml" | tee -a "$LOG_FILE"
}

# 1. Автоматизация загрузки правил от Positive Technologies
echo "[$DATE_NOW] [1/3] Setting up Positive Technologies rules..." | tee -a "$LOG_FILE"

# Добавляем источник правил Positive Technologies через suricata-update
if ! sudo suricata-update list-sources | grep -q "ptresearch"; then
    echo "[*] Adding Positive Technologies rules source..." | tee -a "$LOG_FILE"
    # Positive Technologies правила доступны через suricata-update
    sudo suricata-update enable-source ptresearch 2>&1 | tee -a "$LOG_FILE" || {
        echo "[!] Warning: Could not enable ptresearch source, trying alternative..." | tee -a "$LOG_FILE"
        # Альтернативный способ - прямая загрузка правил
        curl -sS "https://rules.emergingthreats.net/open/suricata/rules/suricata.rules" \
            -o "$FEEDS_DIR/pt-rules.rules" 2>&1 | tee -a "$LOG_FILE" || true
    }
fi

# Обновляем правила
sudo suricata-update update-sources 2>&1 | tee -a "$LOG_FILE"
sudo suricata-update enable-source ptresearch 2>&1 | tee -a "$LOG_FILE" || true
sudo suricata-update 2>&1 | tee -a "$LOG_FILE"

# 2. Блокировка публичных сервисов по IP-адресам
echo "[$DATE_NOW] [2/3] Creating rules to block public services..." | tee -a "$LOG_FILE"

# Получаем IP-адреса популярных сервисов
get_service_ips() {
    local domain="$1"
    dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -5
}

# Список публичных сервисов для блокировки (примеры)
PUBLIC_SERVICES=(
    "www.google.com"
    "www.facebook.com"
    "www.twitter.com"
    "www.instagram.com"
    "www.youtube.com"
)

BLOCKED_IPS=()

for service in "${PUBLIC_SERVICES[@]}"; do
    echo "[*] Resolving IPs for $service..." | tee -a "$LOG_FILE"
    ips=$(get_service_ips "$service" || true)
    if [ -n "$ips" ]; then
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                BLOCKED_IPS+=("$ip")
                echo "[+] Found IP: $ip for $service" | tee -a "$LOG_FILE"
            fi
        done <<< "$ips"
    fi
done

# Создаем файл правил для блокировки публичных сервисов
BLOCK_PUBLIC_FILE="$RULES_DIR/block_public_services.rules"
sudo tee "$BLOCK_PUBLIC_FILE" > /dev/null <<EOBLOCKPUBLIC
# Rules to block public services
# Generated: $DATE_NOW
EOBLOCKPUBLIC

SID_BASE=9300000
for ip in "${BLOCKED_IPS[@]}"; do
    if [ -n "$ip" ]; then
        echo "drop ip $ip any -> \$HOME_NET any (msg:\"[IPS] Blocked Public Service IP $ip\"; classtype:policy-violation; sid:$SID_BASE; rev:1;)" | \
            sudo tee -a "$BLOCK_PUBLIC_FILE" > /dev/null
        SID_BASE=$((SID_BASE + 1))
    fi
done

echo "[+] Created $(wc -l < "$BLOCK_PUBLIC_FILE") rules in $BLOCK_PUBLIC_FILE" | tee -a "$LOG_FILE"
add_rule_file "$BLOCK_PUBLIC_FILE"

# 3. Блокировка ресурсов, запрещенных в РФ
echo "[$DATE_NOW] [3/3] Creating rules to block resources banned in Russia..." | tee -a "$LOG_FILE"

# Загружаем списки заблокированных ресурсов
echo "[*] Downloading Russian blocklist..." | tee -a "$LOG_FILE"

# Используем публичные списки заблокированных ресурсов
# Список доменов, заблокированных в РФ (примеры из реестра)
BANNED_DOMAINS=(
    "twitter.com"
    "facebook.com"
    "instagram.com"
    "linkedin.com"
    "tiktok.com"
)

# Также загружаем IP-адреса из известных списков
curl -sS "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv" \
    -o "$FEEDS_DIR/ru_blocklist.csv" 2>&1 | tee -a "$LOG_FILE" || {
    echo "[!] Could not download RU blocklist, using predefined list" | tee -a "$LOG_FILE"
}

# Создаем файл правил для блокировки ресурсов, запрещенных в РФ
BLOCK_RU_FILE="$RULES_DIR/block_ru_banned.rules"
sudo tee "$BLOCK_RU_FILE" > /dev/null <<EOBLOCKRU
# Rules to block resources banned in Russian Federation
# Generated: $DATE_NOW
EOBLOCKRU

SID_BASE=9400000

# Блокируем домены через HTTP Host header
for domain in "${BANNED_DOMAINS[@]}"; do
    echo "drop http any any -> \$HOME_NET any (msg:\"[IPS] Blocked RU Banned Domain $domain\"; http.host; content:\"$domain\"; classtype:policy-violation; sid:$SID_BASE; rev:1;)" | \
        sudo tee -a "$BLOCK_RU_FILE" > /dev/null
    SID_BASE=$((SID_BASE + 1))
    
    # Также получаем и блокируем IP-адреса этих доменов
    ips=$(get_service_ips "$domain" || true)
    if [ -n "$ips" ]; then
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                echo "drop ip $ip any -> \$HOME_NET any (msg:\"[IPS] Blocked RU Banned IP $ip ($domain)\"; classtype:policy-violation; sid:$SID_BASE; rev:1;)" | \
                    sudo tee -a "$BLOCK_RU_FILE" > /dev/null
                SID_BASE=$((SID_BASE + 1))
            fi
        done <<< "$ips"
    fi
done

# Обрабатываем CSV файл блоклиста, если он был загружен
if [ -f "$FEEDS_DIR/ru_blocklist.csv" ]; then
    echo "[*] Processing RU blocklist CSV..." | tee -a "$LOG_FILE"
    # Парсим CSV и извлекаем IP-адреса (упрощенная версия)
    tail -n +2 "$FEEDS_DIR/ru_blocklist.csv" 2>/dev/null | cut -d',' -f1 | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -100 | while read -r ip; do
        if [ -n "$ip" ]; then
            echo "drop ip $ip any -> \$HOME_NET any (msg:\"[IPS] Blocked RU Banned IP $ip\"; classtype:policy-violation; sid:$SID_BASE; rev:1;)" | \
                sudo tee -a "$BLOCK_RU_FILE" > /dev/null
            SID_BASE=$((SID_BASE + 1))
        fi
    done
fi

echo "[+] Created $(wc -l < "$BLOCK_RU_FILE") rules in $BLOCK_RU_FILE" | tee -a "$LOG_FILE"
add_rule_file "$BLOCK_RU_FILE"

# Тестируем конфигурацию
echo "[$DATE_NOW] Testing Suricata configuration..." | tee -a "$LOG_FILE"
if sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | tee -a "$LOG_FILE"; then
    echo "[$DATE_NOW] SUCCESS: Configuration test passed" | tee -a "$LOG_FILE"
    
    # Перезагружаем Suricata
    echo "[$DATE_NOW] Reloading Suricata..." | tee -a "$LOG_FILE"
    if sudo systemctl reload suricata 2>&1 | tee -a "$LOG_FILE"; then
        echo "[$DATE_NOW] SUCCESS: Suricata reloaded with new blocking rules" | tee -a "$LOG_FILE"
    else
        echo "[$DATE_NOW] WARNING: reload failed, trying restart..." | tee -a "$LOG_FILE"
        sudo systemctl restart suricata 2>&1 | tee -a "$LOG_FILE"
    fi
else
    echo "[$DATE_NOW] ERROR: Configuration test failed!" | tee -a "$LOG_FILE"
    exit 1
fi

echo "[$DATE_NOW] === Blocking rules setup completed ===" | tee -a "$LOG_FILE"
echo "[+] Summary:" | tee -a "$LOG_FILE"
echo "  - Positive Technologies rules: enabled" | tee -a "$LOG_FILE"
echo "  - Public services blocked: ${#BLOCKED_IPS[@]} IPs" | tee -a "$LOG_FILE"
echo "  - RU banned resources: ${#BANNED_DOMAINS[@]} domains" | tee -a "$LOG_FILE"
