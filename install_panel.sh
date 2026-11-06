#!/bin/ash
# Установщик Chernox для OpenWrt: sing-box, tproxy, DNS и веб-панель.
# Запускать на роутере от root: sh install_panel.sh

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PANEL_SRC="$SCRIPT_DIR/panel.py"
PANEL_DIR="/usr/lib/singbox-panel"
PANEL_BIN="$PANEL_DIR/panel.py"
CONFIG_DIR="/etc/singbox-panel"
CONFIG_PATH="$CONFIG_DIR/config.json"
REPO_RAW="https://github.com/donttracked/chernox/raw/HEAD"

if [ "$(id -u)" != "0" ]; then
    echo "Запустите установщик от root."
    exit 1
fi

download_file() {
    url="$1"
    dest="$2"
    tmp="$dest.tmp.$$"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$tmp" || { rm -f "$tmp"; return 1; }
    else
        wget -qO "$tmp" "$url" || { rm -f "$tmp"; return 1; }
    fi

    [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$dest"
}

if [ ! -f "$PANEL_SRC" ]; then
    echo "Скачиваю panel.py..."
    if ! download_file "$REPO_RAW/panel.py" "$PANEL_SRC"; then
        echo "Не удалось скачать panel.py. Скачайте папку репозитория целиком."
        exit 1
    fi
fi

if [ ! -f "$SCRIPT_DIR/author.json" ]; then
    download_file "$REPO_RAW/author.json" "$SCRIPT_DIR/author.json" || true
fi

printf 'Порт панели [8080]: '
read PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}

case "$PANEL_PORT" in
    ''|*[!0-9]*)
        echo "Порт должен быть числом."
        exit 1
        ;;
esac

if [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
    echo "Порт должен быть от 1 до 65535."
    exit 1
fi

printf 'Пароль панели (пусто — сгенерировать): '
stty -echo 2>/dev/null || true
read PANEL_PASSWORD
stty echo 2>/dev/null || true
printf '\n'

GENERATED_PASSWORD=0
if [ -z "$PANEL_PASSWORD" ]; then
    GENERATED_PASSWORD=1
fi

printf 'Автоподъем sing-box при восстановлении интернета? [Y/n]: '
read AUTO_START_ANSWER
case "$AUTO_START_ANSWER" in
    n|N|no|NO|0|off|OFF)
        AUTO_START=0
        ;;
    *)
        AUTO_START=1
        ;;
esac

echo "Обновляю список пакетов..."
opkg update || true

echo "Устанавливаю sing-box, tproxy, DNS и Python..."
for pkg in \
    sing-box \
    dnscrypt-proxy2 \
    kmod-nf-tproxy \
    kmod-nft-tproxy \
    nftables \
    jsonfilter \
    python3 \
    python3-sqlite3 \
    python3-openssl \
    python3-urllib
do
    opkg install "$pkg" || echo "Внимание: не удалось установить $pkg"
done

PYTHON_CHECK='import argparse, hashlib, hmac, html, json, os, secrets, shutil, sqlite3, subprocess, sys, tempfile, threading, time, traceback, http.server, urllib.parse; hashlib.pbkdf2_hmac("sha256", b"x", b"y", 1)'

if ! python3 -c "$PYTHON_CHECK" >/dev/null 2>&1; then
    echo "В Python не хватает нужных модулей (sqlite3, ssl/hashlib, urllib и т.д.)."
    exit 1
fi

if [ "$GENERATED_PASSWORD" = "1" ]; then
    PANEL_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(9))')
    if [ -z "$PANEL_PASSWORD" ]; then
        echo "Не удалось сгенерировать пароль."
        exit 1
    fi
fi

command -v sing-box >/dev/null 2>&1 || {
    echo "sing-box не установлен."
    exit 1
}

[ -x /etc/init.d/dnscrypt-proxy ] || {
    echo "dnscrypt-proxy не установлен."
    exit 1
}

command -v jsonfilter >/dev/null 2>&1 || {
    echo "jsonfilter не установлен."
    exit 1
}

# ---------------------------------------------------------------------------
# sing-box + tproxy + DNS
# ---------------------------------------------------------------------------

mkdir -p /etc/sing-box /usr/share/sing-box
[ -f /etc/sing-box/config.json ] || : > /etc/sing-box/config.json

uci set sing-box.main=sing-box
uci set sing-box.main.enabled='1'
uci set sing-box.main.user='root'
uci set sing-box.main.conffile='/etc/sing-box/config.json'
uci set sing-box.main.workdir='/usr/share/sing-box'
uci commit sing-box

cat > /usr/bin/singbox-tproxy.sh <<'EOF'
#!/bin/sh

TPROXY_PORT=12345
BYPASS_RULE='iifname "br-lan" ip daddr @singbox_bypass return'
TCP_RULE='iifname "br-lan" meta l4proto tcp tproxy ip to :12345 meta mark set 0x00000001 accept'
UDP_RULE='iifname "br-lan" meta l4proto udp tproxy ip to :12345 meta mark set 0x00000001 accept'
BYPASS_ELEMENTS='{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }'

rule_exists() {
    nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -Fq "$1"
}

set_ready() {
    nft list set inet fw4 singbox_bypass >/dev/null 2>&1 || \
        nft add set inet fw4 singbox_bypass '{ type ipv4_addr; flags interval; }'

    nft list set inet fw4 singbox_bypass 2>/dev/null | grep -Fq '0.0.0.0/8' || \
        nft add element inet fw4 singbox_bypass "$BYPASS_ELEMENTS"
}

delete_rule() {
    local rule="$1"
    local handle

    while true; do
        handle=$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep -F "$rule" | sed -n 's/.*# handle \([0-9][0-9]*\)$/\1/p' | head -n 1)
        [ -n "$handle" ] || break
        nft delete rule inet fw4 mangle_prerouting handle "$handle"
    done
}

enable() {
    set_ready || return 1

    rule_exists "$BYPASS_RULE" || nft add rule inet fw4 mangle_prerouting iifname "br-lan" ip daddr @singbox_bypass return
    rule_exists "$TCP_RULE" || nft add rule inet fw4 mangle_prerouting iifname "br-lan" meta l4proto tcp tproxy ip to :$TPROXY_PORT meta mark set 0x1 accept
    rule_exists "$UDP_RULE" || nft add rule inet fw4 mangle_prerouting iifname "br-lan" meta l4proto udp tproxy ip to :$TPROXY_PORT meta mark set 0x1 accept

    ip rule show | grep -q 'fwmark 0x1 lookup vpn' || ip rule add fwmark 0x1 lookup vpn priority 100
    ip route replace table vpn local 0.0.0.0/0 dev lo
}

disable() {
    delete_rule "$TCP_RULE"
    delete_rule "$UDP_RULE"

    while ip rule show | grep -q 'fwmark 0x1 lookup vpn'; do
        ip rule del fwmark 0x1 lookup vpn 2>/dev/null || break
    done
}

sync_state() {
    if pidof sing-box >/dev/null 2>&1; then
        enable
    else
        disable
    fi
}

case "$1" in
    enable)
        enable
        ;;
    disable)
        disable
        ;;
    sync|"")
        sync_state
        ;;
    *)
        echo "Usage: $0 [enable|disable|sync]" >&2
        exit 1
        ;;
esac
EOF

chmod 755 /usr/bin/singbox-tproxy.sh

if [ ! -f /etc/firewall.user ]; then
    printf '#!/bin/sh\n' > /etc/firewall.user
fi
grep -q '/usr/bin/singbox-tproxy.sh sync' /etc/firewall.user || \
    echo '/usr/bin/singbox-tproxy.sh sync' >> /etc/firewall.user
chmod +x /etc/firewall.user

mkdir -p /etc/iproute2
grep -qE '^[[:space:]]*99[[:space:]]+vpn([[:space:]]|$)' /etc/iproute2/rt_tables 2>/dev/null || \
    echo '99 vpn' >> /etc/iproute2/rt_tables

uci set network.chernox_rule=rule
uci set network.chernox_rule.priority='100'
uci set network.chernox_rule.mark='0x1'
uci set network.chernox_rule.lookup='vpn'

uci set network.chernox_route=route
uci set network.chernox_route.interface='loopback'
uci set network.chernox_route.target='0.0.0.0'
uci set network.chernox_route.netmask='0.0.0.0'
uci set network.chernox_route.table='vpn'
uci set network.chernox_route.type='local'
uci commit network

mkdir -p /etc/hotplug.d/iface
cat > /etc/hotplug.d/iface/30-vpnroute <<'EOF'
#!/bin/sh

sleep 5
ip route replace table vpn local 0.0.0.0/0 dev lo
EOF
chmod +x /etc/hotplug.d/iface/30-vpnroute

uci set firewall.chernox_include=include
uci set firewall.chernox_include.type='script'
uci set firewall.chernox_include.path='/etc/firewall.user'
uci set firewall.chernox_include.fw4_compatible='1'
uci commit firewall

cat > /root/config.ini <<EOF
[DEFAULT]
auto_start_singbox = $AUTO_START
EOF

DNSCRYPT_TOML="/etc/dnscrypt-proxy2/dnscrypt-proxy.toml"
if [ -f "$DNSCRYPT_TOML" ]; then
    sed -i "s|^[#[:space:]]*server_names[[:space:]]*=.*|server_names = ['cs-czech', 'cs-finland', 'cs-ch', 'cs-brazil', 'cs-austria', 'dct-fr', 'dct-de', 'deffer-dns.au', 'dnscry.pt-allentown-ipv4', 'dnscry.pt-amsterdam02-ipv4']|" "$DNSCRYPT_TOML"
    grep -q '^server_names' "$DNSCRYPT_TOML" || \
        echo "server_names = ['cs-czech', 'cs-finland', 'cs-ch', 'cs-brazil', 'cs-austria', 'dct-fr', 'dct-de', 'deffer-dns.au', 'dnscry.pt-allentown-ipv4', 'dnscry.pt-amsterdam02-ipv4']" >> "$DNSCRYPT_TOML"
fi

if uci -q get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
    uci -q delete dhcp.@dnsmasq[0].server
    uci add_list dhcp.@dnsmasq[0].server='127.0.0.53'
    uci set dhcp.@dnsmasq[0].noresolv='1'
    uci set dhcp.@dnsmasq[0].localuse='1'
    uci commit dhcp
fi

ip rule show | grep -q 'fwmark 0x1 lookup vpn' || ip rule add fwmark 0x1 lookup vpn priority 100
ip route replace table vpn local 0.0.0.0/0 dev lo

/etc/init.d/dnscrypt-proxy enable
/etc/init.d/dnscrypt-proxy restart
/etc/init.d/dnsmasq restart
/etc/init.d/firewall reload >/dev/null 2>&1 || true

/etc/init.d/sing-box enable
if [ -s /etc/sing-box/config.json ]; then
    /etc/init.d/sing-box restart
fi
/usr/bin/singbox-tproxy.sh sync

cat > /usr/bin/check-internet.sh <<'EOF'
#!/bin/sh

START_COMMAND="/etc/init.d/sing-box start"
TPROXY_HELPER="/usr/bin/singbox-tproxy.sh"
CONFIG_FILE="/etc/sing-box/config.json"
SETTINGS_FILE="/root/config.ini"
LOG_FILE="/tmp/internet-check.log"
MANUAL_STOP_FILE="/tmp/singbox-manual-stop"
MAX_ERRORS=2
RESET_THRESHOLD=300
CONNECT_TIMEOUT=5

is_auto_start_enabled() {
    if [ ! -f "$SETTINGS_FILE" ]; then
        return 1
    fi

    value=$(sed -n 's/^[[:space:]]*auto_start_singbox[[:space:]]*=[[:space:]]*//p' "$SETTINGS_FILE" | tail -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')

    case "$value" in
        1|yes|true|on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

get_remote_address() {
    jsonfilter -i "$CONFIG_FILE" -e '@.outbounds[@.tag="ssh-out"].server' 2>/dev/null
}

get_remote_port() {
    jsonfilter -i "$CONFIG_FILE" -e '@.outbounds[@.tag="ssh-out"].server_port' 2>/dev/null
}

is_remote_available() {
    local remote_address remote_port nc_pid elapsed

    [ -s "$CONFIG_FILE" ] || return 1

    remote_address=$(get_remote_address)
    remote_port=$(get_remote_port)

    [ -n "$remote_address" ] || return 1
    [ -n "$remote_port" ] || return 1

    nc "$remote_address" "$remote_port" < /dev/null > /dev/null 2>&1 &
    nc_pid=$!
    elapsed=0

    while kill -0 "$nc_pid" 2>/dev/null; do
        if [ "$elapsed" -ge "$CONNECT_TIMEOUT" ]; then
            kill "$nc_pid" 2>/dev/null
            wait "$nc_pid" 2>/dev/null
            return 1
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    wait "$nc_pid"
}

if [ ! -f "$LOG_FILE" ]; then
    echo "0 $(date +%s)" > "$LOG_FILE"
fi

read ERRORS LAST_CHECK_TIME < "$LOG_FILE"
CURRENT_TIME=$(date +%s)

if [ $((CURRENT_TIME - LAST_CHECK_TIME)) -gt "$RESET_THRESHOLD" ]; then
    ERRORS=0
fi

if [ -f "$MANUAL_STOP_FILE" ]; then
    echo "0 $(date +%s)" > "$LOG_FILE"
    $TPROXY_HELPER disable > /dev/null 2>&1
    exit 0
fi

if ! is_remote_available; then
    ERRORS=$((ERRORS + 1))
    echo "$ERRORS $CURRENT_TIME" > "$LOG_FILE"

    if [ "$ERRORS" -ge "$MAX_ERRORS" ]; then
        logger -t check-internet 'Remote sing-box endpoint is unavailable, disabling tproxy'
        $TPROXY_HELPER disable > /dev/null 2>&1
        echo "0 $(date +%s)" > "$LOG_FILE"
    fi
else
    echo "0 $(date +%s)" > "$LOG_FILE"

    if pidof sing-box > /dev/null 2>&1; then
        $TPROXY_HELPER enable > /dev/null 2>&1
    elif is_auto_start_enabled && [ -s "$CONFIG_FILE" ]; then
        logger -t check-internet 'Remote sing-box endpoint is available, starting sing-box and enabling tproxy'
        $START_COMMAND > /dev/null 2>&1
        sleep 10

        if pidof sing-box > /dev/null 2>&1; then
            $TPROXY_HELPER enable > /dev/null 2>&1
        else
            $TPROXY_HELPER disable > /dev/null 2>&1
        fi
    else
        $TPROXY_HELPER disable > /dev/null 2>&1
    fi
fi
EOF

chmod 755 /usr/bin/check-internet.sh

cat > /etc/init.d/check-internet <<'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=15

USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh -c "while true; do /usr/bin/check-internet.sh; sleep 45; done"
    procd_set_param respawn
    procd_close_instance
}

stop_service() {
    PIDS=$(pidof check-internet.sh)
    if [ -n "$PIDS" ]; then
        for PID in $PIDS; do
            kill $PID
        done
    fi
}

status_service() {
    if pgrep -f "check-internet.sh" > /dev/null; then
        echo "Service is running"
    else
        echo "Service is not running"
    fi
}
EOF

chmod 755 /etc/init.d/check-internet
/etc/init.d/check-internet enable
/etc/init.d/check-internet restart

# ---------------------------------------------------------------------------
# Chernox
# ---------------------------------------------------------------------------

if ! printf '%s\n' "$PANEL_PASSWORD" | python3 "$PANEL_SRC" \
    --config "$CONFIG_PATH" --init --host 0.0.0.0 --port "$PANEL_PORT"; then
    echo "Не удалось создать настройки панели."
    exit 1
fi

mkdir -p "$PANEL_DIR" "$CONFIG_DIR"
cp "$PANEL_SRC" "$PANEL_BIN"
chmod 755 "$PANEL_BIN"
chmod 700 "$CONFIG_DIR"

if [ -f "$SCRIPT_DIR/author.json" ] && [ ! -f "$CONFIG_DIR/author.json" ]; then
    cp "$SCRIPT_DIR/author.json" "$CONFIG_DIR/author.json"
fi

chmod 600 "$CONFIG_PATH" 2>/dev/null || true
chmod 600 "$CONFIG_DIR/panel.db" 2>/dev/null || true
chmod 600 "$CONFIG_DIR/author.json" 2>/dev/null || true

cat <<'EOF' > /etc/init.d/singbox-panel
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/python3 /usr/lib/singbox-panel/panel.py --config /etc/singbox-panel/config.json
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    PIDS=$(pgrep -f "/usr/lib/singbox-panel/panel.py")
    if [ -n "$PIDS" ]; then
        for PID in $PIDS; do
            kill "$PID"
        done
    fi
}
EOF

chmod 755 /etc/init.d/singbox-panel

uci set firewall.singbox_panel=rule
uci set firewall.singbox_panel.name='singbox-panel'
uci set firewall.singbox_panel.src='lan'
uci set firewall.singbox_panel.proto='tcp'
uci set firewall.singbox_panel.dest_port="$PANEL_PORT"
uci set firewall.singbox_panel.target='ACCEPT'
uci commit firewall
/etc/init.d/firewall reload >/dev/null 2>&1 || true

/etc/init.d/singbox-panel enable
/etc/init.d/singbox-panel restart
sleep 2

if ! pgrep -f "/usr/lib/singbox-panel/panel.py" >/dev/null 2>&1; then
    echo
    echo "Внимание: панель не запустилась. Проверьте: logread -e singbox-panel"
fi

LAN_IP=$(uci get network.lan.ipaddr 2>/dev/null || true)
case "$LAN_IP" in
    ''|'dhcp'|'none'|*/*)
        LAN_IP=$(ip -4 addr show br-lan 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -n 1)
        ;;
esac
[ -n "$LAN_IP" ] || LAN_IP="<IP-роутера>"

echo
echo "Chernox установлен."
echo "Адрес:   http://$LAN_IP:$PANEL_PORT"
if [ "$GENERATED_PASSWORD" = "1" ]; then
    echo "Пароль:  $PANEL_PASSWORD"
else
    echo "Пароль:  заданный вами"
fi
echo "Данные:  $CONFIG_PATH"
echo "База:    $CONFIG_DIR/panel.db"
echo "Ключи:   vless, hysteria2, ssh"
