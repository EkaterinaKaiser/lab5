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
sudo tee /etc/suricata/rules/local.rules > /dev/null <<'EORULES'
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
sudo setcap cap_net_admin,cap_net_raw+ep /usr/bin/suricata
sudo mkdir -p /etc/systemd/system/suricata.service.d
sudo tee /etc/systemd/system/suricata.service.d/override.conf > /dev/null <<'EOSERVICE'
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 1 --pidfile /run/suricata.pid
EOSERVICE

# Запуск Suricata
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl restart suricata
sudo systemctl status suricata --no-pager

sudo apt-get install curl
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://evebox.org/files/GPG-KEY-evebox | sudo tee /etc/apt/keyrings/evebox.asc > /dev/null
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

sudo docker stop root-evebox-1 2>/dev/null || true
sudo docker rm root-evebox-1 2>/dev/null || true

sudo docker run -d \
  --name root-evebox-1 \
  -v /var/log/suricata:/var/log/suricata:ro \
  -p 5636:5636 \
  jasonish/evebox:latest \
  evebox server --host 0.0.0.0 --port 5636 --input /var/log/suricata/eve.json

sleep 10

sudo suricata-update update-sources
sudo suricata-update enable-source et/open
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl status suricata --no-pager

sudo mkdir -p /opt/suricata-tools
cat > /tmp/update_rules.sh <<'EOSCRIPT'
#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/suricata/update_rules.log"
DATE_NOW="$(date -Iseconds)"
echo "[$DATE_NOW] === Starting Suricata rules update ===" | tee -a "$LOG_FILE"
echo "[$DATE_NOW] [1/3] Fetch + merge rules via suricata-update..." | tee -a "$LOG_FILE"
if ! suricata-update >>"$LOG_FILE" 2>&1; then
    echo "[$DATE_NOW] ERROR: suricata-update failed, aborting." | tee -a "$LOG_FILE"
    exit 1
fi
echo "[$DATE_NOW] [2/3] Test Suricata configuration..." | tee -a "$LOG_FILE"
if ! suricata -T -c /etc/suricata/suricata.yaml >>"$LOG_FILE" 2>&1; then
    echo "[$DATE_NOW] ERROR: suricata -T failed, NOT reloading service." | tee -a "$LOG_FILE"
    exit 1
fi
echo "[$DATE_NOW] [3/3] Reload Suricata service..." | tee -a "$LOG_FILE"
if systemctl reload suricata 2>>"$LOG_FILE"; then
    echo "[$DATE_NOW] SUCCESS: Rules updated and Suricata reloaded." | tee -a "$LOG_FILE"
else
    echo "[$DATE_NOW] WARNING: reload failed, trying restart..." | tee -a "$LOG_FILE"
    systemctl restart suricata
fi
EOSCRIPT
sudo mv /tmp/update_rules.sh /opt/suricata-tools/update_rules.sh
sudo chmod +x /opt/suricata-tools/update_rules.sh
sudo /opt/suricata-tools/update_rules.sh
sudo tail -n 20 /var/log/suricata/update_rules.log

mkdir -p ~/suricata-ioc/feeds
cd ~/suricata-ioc
cat > ~/suricata-ioc/fetch_feeds.sh <<'EOFEEDS'
#!/usr/bin/env bash
set -euo pipefail
FEEDS_DIR="$(dirname "$0")/feeds"
mkdir -p "$FEEDS_DIR"
echo "[*] Downloading Feodo Tracker IP blocklist..."
curl -sS "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" \
  -o "${FEEDS_DIR}/feodo_ips.txt"
echo "[*] Downloading URLhaus IP blocklist..."
curl -sS "https://urlhaus.abuse.ch/downloads/text_ips/" \
  -o "${FEEDS_DIR}/urlhaus_ips.txt"
echo "[*] Downloading Botvrij.eu Destination IPs..."
curl -sS "https://www.botvrij.eu/data/ioclist.ip-dst.raw" \
  -o "${FEEDS_DIR}/botvrij_ips.txt"
echo "[*] Done. Feeds saved to: ${FEEDS_DIR}"
ls -lh "${FEEDS_DIR}"
EOFEEDS
chmod +x ~/suricata-ioc/fetch_feeds.sh

~/suricata-ioc/fetch_feeds.sh

cat > ~/suricata-ioc/generate_custom_ioc_rules.py <<'EOPYTHON'
#!/usr/bin/env python3
"""
Генерация custom_ioc.rules из IoC-источников
"""
from pathlib import Path
from datetime import datetime
import sys

# Конфигурация диапазонов SID для разных источников
SOURCES = {
    "feodo": {
        "file": "feodo_ips.txt",
        "base_sid": 9000000,
        "msg_prefix": "[IPS] Feodo Tracker C&C",
        "classtype": "trojan-activity"
    },
    "urlhaus": {
        "file": "urlhaus_ips.txt",
        "base_sid": 9100000,
        "msg_prefix": "[IPS] URLhaus Malicious IP",
        "classtype": "trojan-activity"
    },
    "botvrij": {
        "file": "botvrij_ips.txt",
        "base_sid": 9200000,
        "msg_prefix": "[IPS] Botvrij.eu IoC",
        "classtype": "trojan-activity"
    }
}

def load_ips(path: Path):
    """Загрузка IP-адресов из текстового файла"""
    ips = []
    if not path.exists():
        print(f"[!] WARNING: File {path} not found, skipping...")
        return ips
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Извлекаем только IP-адрес (первое поле)
            ip = line.split(',')[0] if ',' in line else line.split()[0]
            # Базовая валидация IPv4
            if '.' in ip:
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        if all(0 <= int(p) <= 255 for p in parts):
                            ips.append(ip)
                    except ValueError:
                        continue
    return ips

def generate_drop_rules(source_name, config, ips):
    """Генерация drop-правил для списка IP"""
    rules = []
    sid = config["base_sid"]
    # Ограничиваем количество правил для практической работы
    max_rules = 1000
    for ip in ips[:max_rules]:
        rule = (
            f"drop ip {ip} any -> $HOME_NET any "
            f'(msg:"{config["msg_prefix"]} {ip}"; '
            f'classtype:{config["classtype"]}; '
            f'sid:{sid}; rev:1;)\n'
        )
        rules.append(rule)
        sid += 1
    return rules, sid

def add_to_yaml_config(rules_file: Path):
    """Добавление custom_ioc.rules в suricata.yaml если его там нет"""
    yaml_file = Path("/etc/suricata/suricata.yaml")
    with yaml_file.open() as f:
        content = f.read()
    if "custom_ioc.rules" in content:
        print("[*] custom_ioc.rules already in suricata.yaml")
        return
    # Ищем секцию rule-files и добавляем наш файл
    lines = content.split('\n')
    new_lines = []
    for i, line in enumerate(lines):
        new_lines.append(line)
        if 'rule-files:' in line:
            # Смотрим на следующие строки для определения отступа
            for j in range(i+1, min(i+5, len(lines))):
                if lines[j].strip().startswith('-'):
                    indent = len(lines[j]) - len(lines[j].lstrip())
                    new_lines.append(' ' * indent + f"- {rules_file}")
                    break
    with yaml_file.open('w') as f:
        f.write('\n'.join(new_lines))
    print(f"[+] Added {rules_file} to suricata.yaml")

def main():
    feeds_dir = Path(__file__).parent / "feeds"
    out_file = Path("/etc/suricata/rules/custom_ioc.rules")
    all_rules = []
    stats = {}
    print("[*] Starting IoC rules generation...\n")
    # Генерация правил для каждого источника
    for source_name, config in SOURCES.items():
        source_file = feeds_dir / config["file"]
        ips = load_ips(source_file)
        if not ips:
            stats[source_name] = 0
            print(f"[!] {source_name.upper()}: No IPs loaded")
            continue
        rules, last_sid = generate_drop_rules(source_name, config, ips)
        all_rules.extend(rules)
        stats[source_name] = len(rules)
        print(f"[+] {source_name.upper()}: Generated {len(rules)} rules "
              f"(SID: {config['base_sid']}-{last_sid-1})")
    if len(all_rules) == 0:
        print("\n[!] ERROR: No rules generated. Check if feeds were downloaded correctly.")
        print("[!] Run ./fetch_feeds.sh first to download IoC feeds.")
        sys.exit(1)
    # Запись всех правил в один файл
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w") as f:
        f.write(f"# Autogenerated IoC-based rules from multiple sources\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total rules: {len(all_rules)}\n")
        f.write(f"# Sources: {', '.join(SOURCES.keys())}\n")
        f.write(f"#\n")
        for source, count in stats.items():
            f.write(f"# - {source}: {count} rules\n")
        f.write(f"\n")
        for rule in all_rules:
            f.write(rule)
    print(f"\n[+] Total: Generated {len(all_rules)} rules into {out_file}")
    # Добавляем файл в конфигурацию Suricata
    add_to_yaml_config(out_file)
    print("\n[*] Done! Run 'sudo /opt/suricata-tools/update_rules.sh' to apply changes.")

if __name__ == "__main__":
    main()
EOPYTHON
chmod +x ~/suricata-ioc/generate_custom_ioc_rules.py

sudo python3 ~/suricata-ioc/generate_custom_ioc_rules.py

sudo wc -l /etc/suricata/rules/custom_ioc.rules
sudo head -20 /etc/suricata/rules/custom_ioc.rules

grep "custom_ioc.rules" /etc/suricata/suricata.yaml

sudo /opt/suricata-tools/update_rules.sh

sudo apt install make

cat > ~/suricata-ioc/Makefile <<'EOMAKEFILE'
.PHONY: all fetch generate test deploy clean status
all: fetch generate test deploy status
fetch:
	@echo "[*] Stage 1/4: Fetching external feeds..."
	@./fetch_feeds.sh
generate:
	@echo "[*] Stage 2/4: Generating custom_ioc.rules..."
	@sudo python3 generate_custom_ioc_rules.py
test:
	@echo "[*] Stage 3/4: Testing Suricata configuration..."
	@sudo suricata -T -c /etc/suricata/suricata.yaml
deploy:
	@echo "[*] Stage 4/4: Deploying rules (reload Suricata)..."
	@sudo systemctl reload suricata || sudo systemctl restart suricata
	@echo "[+] Pipeline completed successfully!"
status:
	@echo "[*] Checking Suricata status..."
	@sudo systemctl status suricata --no-pager | head -10
clean:
	@echo "[*] Cleaning feeds directory..."
	@rm -rf feeds/
EOMAKEFILE

cd ~/suricata-ioc
make all

# Установка dnsutils для команды dig (используется в setup_blocking_rules.sh)
sudo apt-get install -y dnsutils
