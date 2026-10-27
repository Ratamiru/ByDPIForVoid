#!/bin/sh
# Установка ByeDPI × TG Desktop (рассчитано на Void Linux, работает и на других дистрах)
#   ./install.sh            — установить / обновить
#   ./install.sh uninstall  — удалить (конфиг в ~/.config/byedpi-tg остаётся)
set -eu

APP="${BYEDPI_TG_HOME:-$HOME/.local/share/byedpi-tg}"
BIN="$HOME/.local/bin"
DESKTOP="$HOME/.local/share/applications"
SRC="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

if [ "${1:-}" = "uninstall" ]; then
    rm -rf "$APP" "$BIN/byedpi-tg" "$DESKTOP/byedpi-tg.desktop"
    say "Удалено. Конфиг оставлен в ~/.config/byedpi-tg"
    exit 0
fi

# 1. Системные пакеты
if command -v xbps-install >/dev/null 2>&1; then
    say "Ставлю зависимости через xbps (нужен sudo)"
    sudo xbps-install -Sy git gcc make python3 curl xdg-utils
elif ! command -v gcc >/dev/null || ! command -v git >/dev/null || ! command -v python3 >/dev/null; then
    echo "Нужны: git, gcc, make, python3, curl, xdg-utils — поставь их пакетным менеджером." >&2
    exit 1
fi

# PySide6 из pip — это glibc-колёса, на musl-Void не встанут
if ldd --version 2>&1 | grep -qi musl; then
    echo "Похоже, у тебя musl-вариант Void: колёса PySide6 из pip не подойдут." >&2
    echo "Поставь PySide6 из системы и пересоздай venv с --system-site-packages." >&2
    exit 1
fi

mkdir -p "$APP" "$BIN" "$DESKTOP"

clone_or_pull() {  # $1 = url, $2 = dir
    if [ -d "$2/.git" ]; then
        git -C "$2" pull --ff-only -q
    else
        git clone --depth 1 -q "$1" "$2"
    fi
}

# 2. byedpi
say "Собираю byedpi"
clone_or_pull https://github.com/hufrea/byedpi "$APP/byedpi"
make -C "$APP/byedpi" -s >/dev/null 2>&1 || make -C "$APP/byedpi"
test -x "$APP/byedpi/ciadpi"

# 3. tg-ws-proxy
say "Качаю tg-ws-proxy"
clone_or_pull https://github.com/Flowseal/tg-ws-proxy "$APP/tg-ws-proxy"

# 4. Python-окружение
say "Создаю venv и ставлю PySide6 + зависимости прокси"
[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q PySide6-Essentials certifi "httpx[http2]" cryptography

# 5. Само приложение
install -m 755 "$SRC/byedpi_tg.py" "$APP/byedpi_tg.py"
install -m 644 "$SRC/strategies.list" "$APP/strategies.list"
cat > "$BIN/byedpi-tg" <<EOF
#!/bin/sh
exec "$APP/venv/bin/python" "$APP/byedpi_tg.py" "\$@"
EOF
chmod +x "$BIN/byedpi-tg"

sed "s|@BIN@|$BIN|" "$SRC/byedpi-tg.desktop" > "$DESKTOP/byedpi-tg.desktop"

say "Готово. Запуск: byedpi-tg  (или через лаунчер приложений)"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "   ~/.local/bin нет в PATH — добавь его или запускай $BIN/byedpi-tg";; esac
