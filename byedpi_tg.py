#!/usr/bin/env python3
"""
ByeDPI × TG Desktop — маленький GUI для Linux (Void и др.).

Запускает два локальных прокси:
  • byedpi (ciadpi)  — SOCKS5 для браузера, обход DPI для сайтов
  • tg-ws-proxy      — MTProto-прокси для Telegram Desktop через WebSocket

Сам ничего не проксирует — только управляет процессами.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PySide6.QtCore import QProcess, QThread, Qt, Signal, QTimer
from PySide6.QtGui import (QAction, QColor, QFont, QGuiApplication, QIcon,
                           QPainter, QPalette, QPixmap)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox,
                               QComboBox, QFrame, QGridLayout, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMainWindow,
                               QMenu, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QSpinBox, QSystemTrayIcon,
                               QTableWidget, QTableWidgetItem, QTabWidget,
                               QVBoxLayout, QWidget)

# ─────────────────────────── пути и конфиг ───────────────────────────

APP_NAME = "ByeDPI × TG"
HERE = Path(__file__).resolve().parent
APP_HOME = Path(os.environ.get("BYEDPI_TG_HOME",
                               Path.home() / ".local/share/byedpi-tg"))
CFG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "byedpi-tg"
CFG_FILE = CFG_DIR / "config.json"
USER_STRATEGIES = CFG_DIR / "strategies.list"      # сюда кладёт «Обновить список»

CIADPI = APP_HOME / "byedpi" / "ciadpi"
TGWS_DIR = APP_HOME / "tg-ws-proxy"
VENV_PY = APP_HOME / "venv" / "bin" / "python"

STRATEGIES_URL = ("https://raw.githubusercontent.com/romanvht/ByeByeDPI/master/"
                  "app/src/main/assets/proxytest_strategies.list")

# Стартовая стратегия до первого подбора (из списка ByeByeDPI, короткая)
DEFAULT_ARGS = "-o1 -d1 -a1 -At,r,s -s1 -d1 -s5+s -s10+s -s15+s -s20+s -r1+s -S -a1 -As -s1 -d1 -s5+s -s10+s -s15+s -s20+s -S -a1"

# Что проверяем при подборе: YouTube (как в ByeByeDPI) + несколько видеосерверов
DEFAULT_TEST_SITES = [
    "youtube.com", "youtu.be", "i.ytimg.com", "yt3.ggpht.com",
    "youtubei.googleapis.com", "jnn-pa.googleapis.com", "manifest.googlevideo.com",
    "yt3.googleusercontent.com",
    "rr1---sn-4axm-n8vs.googlevideo.com", "rr4---sn-q4flrnsl.googlevideo.com",
    "rr2---sn-q4fl6ndl.googlevideo.com", "rr5---sn-n8v7knez.googlevideo.com",
]

DEFAULT_CFG = {
    "byedpi_port": 1080,
    "byedpi_args": DEFAULT_ARGS,
    "fake_sni": "google.com",
    "tg_port": 1443,
    "tg_secret": "",
    "tg_extra_args": "",
    "browser_cmd": "chromium --proxy-server=socks5://127.0.0.1:{port}",
    "test_sites": DEFAULT_TEST_SITES,
    "test_timeout": 5,
    "favorites": [],            # [[score, total, args], …] — лучшие из последнего подбора
    "autostart_byedpi": False,
    "autostart_tg": False,
    "start_hidden": False,
}


def load_cfg() -> dict:
    cfg = dict(DEFAULT_CFG)
    try:
        cfg.update(json.loads(CFG_FILE.read_text()))
    except (OSError, ValueError):
        pass
    if not cfg["tg_secret"]:
        # секрет храним постоянно, чтобы прокси в Telegram не приходилось перенастраивать
        cfg["tg_secret"] = secrets.token_hex(16)
        save_cfg(cfg)
    return cfg


def save_cfg(cfg: dict) -> None:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    CFG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))


def load_strategies() -> list[str]:
    for path in (USER_STRATEGIES, APP_HOME / "strategies.list", HERE / "strategies.list"):
        try:
            lines = [l.strip() for l in path.read_text().splitlines()]
            lines = [l for l in lines if l and not l.startswith("#")]
            if lines:
                return lines
        except OSError:
            continue
    return [DEFAULT_ARGS]


def expand_args(args: str, sni: str) -> list[str]:
    """{sni} → значение, затем разбор как в shell."""
    return shlex.split(args.replace("{sni}", shlex.quote(sni or "google.com")))


def port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def site_ok(port: int, site: str, timeout: int = 5) -> bool:
    """
    Сайт считается рабочим, только если ответ скачался ЦЕЛИКОМ.
    ТСПУ часто пропускает TLS-рукопожатие и «замораживает» соединение после ~16 КБ —
    тогда curl упадёт по таймауту (28) или недокачке (18), и это засчитается как провал.
    """
    url = site if "://" in site else f"https://{site}"
    try:
        r = subprocess.run(
            ["curl", "-s", "-L", "--max-redirs", "3", "-o", "/dev/null",
             "-w", "%{http_code}", "-m", str(timeout),
             "-x", f"socks5h://127.0.0.1:{port}", url],
            capture_output=True, text=True, timeout=timeout + 3)
        return r.returncode == 0 and r.stdout.strip() not in ("", "000")
    except (OSError, subprocess.TimeoutExpired):
        return False


def check_sites(port: int, sites: list[str], timeout: int) -> int:
    with ThreadPoolExecutor(max_workers=min(16, len(sites) or 1)) as ex:
        return sum(ex.map(lambda s: site_ok(port, s, timeout), sites))


# ─────────────────────────── DNS-диагностика ───────────────────────────

# Основные подсети Google/YouTube. Если системный DNS отдаёт что-то вне них — похоже на подмену.
GOOGLE_NETS = [ipaddress.ip_network(n) for n in (
    "8.8.4.0/24", "8.8.8.0/24", "34.0.0.0/9", "35.184.0.0/13", "64.233.160.0/19",
    "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18", "74.125.0.0/16",
    "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16",
    "173.194.0.0/16", "192.178.0.0/15", "209.85.128.0/17", "216.58.192.0/19",
    "216.239.32.0/19", "2001:4860::/32", "2404:6800::/32", "2607:f8b0::/32",
    "2800:3f0::/32", "2a00:1450::/32", "2c0f:fb50::/32")]

DNS_TEST_HOSTS = ["www.youtube.com", "i.ytimg.com", "rr1---sn-4axm-n8vs.googlevideo.com"]


def is_google_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in GOOGLE_NETS)


def system_resolve(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def doh_resolve(host: str, socks_port: int | None) -> list[str]:
    """DNS-over-HTTPS (JSON API). Сначала напрямую, потом через byedpi, если он запущен."""
    endpoints = [
        f"https://dns.google/resolve?name={host}&type=A",
        f"https://cloudflare-dns.com/dns-query?name={host}&type=A",
        f"https://dns.quad9.net:5053/dns-query?name={host}&type=A",
    ]
    routes = [None] + ([socks_port] if socks_port else [])
    for via in routes:
        for url in endpoints:
            cmd = ["curl", "-s", "-m", "5", "-H", "accept: application/dns-json", url]
            if via:
                cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{via}"]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
                data = json.loads(out)
                ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                if ips:
                    return sorted(set(ips))
            except (OSError, ValueError, subprocess.TimeoutExpired):
                continue
    return []


# ─────────────────────────── виджеты ───────────────────────────

def dot_pixmap(color: str, size: int = 12) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.end()
    return pm


def tray_icon(sites_on: bool, tg_on: bool) -> QIcon:
    """Иконка трея: левая половина — сайты, правая — Telegram."""
    s = 64
    pm = QPixmap(s, s)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#3ddc84" if sites_on else "#555b66"))
    p.drawPie(4, 4, s - 8, s - 8, 90 * 16, 180 * 16)
    p.setBrush(QColor("#2aa3e6" if tg_on else "#3c414a"))
    p.drawPie(4, 4, s - 8, s - 8, 270 * 16, 180 * 16)
    p.end()
    return QIcon(pm)


class Card(QFrame):
    def __init__(self, title: str):
        super().__init__()
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(10)
        head = QHBoxLayout()
        self.dot = QLabel()
        self.dot.setPixmap(dot_pixmap("#555b66"))
        t = QLabel(title)
        t.setObjectName("cardTitle")
        self.status = QLabel("Остановлен")
        self.status.setObjectName("status")
        self.toggle = QPushButton("Запустить")
        self.toggle.setObjectName("toggle")
        self.toggle.setCheckable(True)
        self.toggle.setMinimumWidth(110)
        head.addWidget(self.dot)
        head.addWidget(t)
        head.addSpacing(8)
        head.addWidget(self.status, 1)
        head.addWidget(self.toggle)
        self.lay.addLayout(head)

    def set_state(self, state: str, text: str | None = None):
        colors = {"on": "#3ddc84", "off": "#555b66", "err": "#ef5350", "wait": "#ffb74d"}
        labels = {"on": "Работает", "off": "Остановлен", "err": "Ошибка", "wait": "Запуск…"}
        self.dot.setPixmap(dot_pixmap(colors[state]))
        self.status.setText(text or labels[state])
        self.toggle.blockSignals(True)
        self.toggle.setChecked(state in ("on", "wait"))
        self.toggle.setText("Остановить" if state in ("on", "wait") else "Запустить")
        self.toggle.blockSignals(False)


class StrategyTester(QThread):
    progress = Signal(int, int, str)      # i, total, args
    result = Signal(str, int, int)        # args, ok, total_sites
    done = Signal(bool)                   # stopped?
    failed = Signal(str)

    def __init__(self, strategies: list[str], sites: list[str], sni: str, timeout: int):
        super().__init__()
        self.strategies, self.sites, self.sni, self.timeout = strategies, sites, sni, timeout
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        n = len(self.strategies)
        for i, args in enumerate(self.strategies):
            if self._stop:
                break
            self.progress.emit(i, n, args)
            port = free_port()
            try:
                argv = expand_args(args, self.sni)
                proc = subprocess.Popen([str(CIADPI), "-i", "127.0.0.1", "-p", str(port), *argv],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, ValueError) as e:
                self.failed.emit(f"Не удалось запустить ciadpi: {e}")
                break
            for _ in range(30):
                if port_busy(port) or proc.poll() is not None:
                    break
                time.sleep(0.05)
            ok = 0 if proc.poll() is not None else check_sites(port, self.sites, self.timeout)
            proc.terminate()
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                proc.kill()
            self.result.emit(args, ok, len(self.sites))
        self.done.emit(self._stop)


class Worker(QThread):
    """Запустить функцию в фоне и вернуть результат сигналом."""
    finished_with = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        self.finished_with.emit(self.fn())


# ─────────────────────────── главное окно ───────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = load_cfg()
        self.quitting = False
        self.tester: StrategyTester | None = None
        self._workers: list[QThread] = []
        self._user_stopped: set[int] = set()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(600, 720)

        self.p_dpi = QProcess(self)
        self.p_tg = QProcess(self)
        for proc, name in ((self.p_dpi, "dpi"), (self.p_tg, "tg")):
            proc.setProcessChannelMode(QProcess.MergedChannels)
            proc.readyReadStandardOutput.connect(lambda p=proc, n=name: self._read(p, n))
            proc.started.connect(lambda n=name: self._started(n))
            proc.finished.connect(lambda code, st, n=name: self._finished(n, code, st))
            proc.errorOccurred.connect(lambda err, n=name: self._error(n, err))

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)
        self.setCentralWidget(central)

        root.addWidget(self._build_dpi_card())
        root.addWidget(self._build_tg_card())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_test_tab(), "Подбор стратегий")
        self.log_dpi = self._log_view()
        self.log_tg = self._log_view()
        self.tabs.addTab(self.log_dpi, "Лог byedpi")
        self.tabs.addTab(self.log_tg, "Лог Telegram")
        root.addWidget(self.tabs, 1)

        opts = QHBoxLayout()
        self.cb_auto_dpi = QCheckBox("Автозапуск сайтов")
        self.cb_auto_tg = QCheckBox("Автозапуск Telegram")
        self.cb_hidden = QCheckBox("Стартовать в трее")
        self.cb_auto_dpi.setChecked(self.cfg["autostart_byedpi"])
        self.cb_auto_tg.setChecked(self.cfg["autostart_tg"])
        self.cb_hidden.setChecked(self.cfg["start_hidden"])
        for cb in (self.cb_auto_dpi, self.cb_auto_tg, self.cb_hidden):
            cb.toggled.connect(self._save_opts)
            opts.addWidget(cb)
        opts.addStretch()
        root.addLayout(opts)

        self._build_tray()
        self._check_install()

        if self.cfg["autostart_byedpi"]:
            QTimer.singleShot(200, self.start_dpi)
        if self.cfg["autostart_tg"]:
            QTimer.singleShot(300, self.start_tg)

    # ---------- построение UI ----------

    def _log_view(self) -> QPlainTextEdit:
        v = QPlainTextEdit()
        v.setReadOnly(True)
        v.setMaximumBlockCount(3000)
        v.setFont(QFont("monospace", 9))
        return v

    def _build_dpi_card(self) -> Card:
        c = Card("Сайты · byedpi")
        self.card_dpi = c
        c.toggle.toggled.connect(lambda on: self.start_dpi() if on else self.stop_dpi())

        g = QGridLayout()
        g.setHorizontalSpacing(8)
        g.addWidget(QLabel("Стратегия"), 0, 0)
        self.preset = QComboBox()
        self.preset.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.preset.setMinimumContentsLength(20)
        g.addWidget(self.preset, 0, 1, 1, 3)

        g.addWidget(QLabel("Аргументы"), 1, 0)
        self.dpi_args = QLineEdit(self.cfg["byedpi_args"])
        self.dpi_args.setCursorPosition(0)
        self.dpi_args.setFont(QFont("monospace", 9))
        self.dpi_args.setPlaceholderText("-o1 -d1 -a1 … ({sni} заменится на Fake SNI)")
        g.addWidget(self.dpi_args, 1, 1, 1, 3)

        g.addWidget(QLabel("Порт SOCKS5"), 2, 0)
        self.dpi_port = QSpinBox()
        self.dpi_port.setRange(1024, 65535)
        self.dpi_port.setValue(self.cfg["byedpi_port"])
        g.addWidget(self.dpi_port, 2, 1)
        g.addWidget(QLabel("Fake SNI"), 2, 2, Qt.AlignRight)
        self.fake_sni = QLineEdit(self.cfg["fake_sni"])
        self.fake_sni.setToolTip("Подставляется вместо {sni} в стратегиях с -n (поддельный ClientHello)")
        g.addWidget(self.fake_sni, 2, 3)
        g.setColumnStretch(1, 1)
        g.setColumnStretch(3, 1)
        c.lay.addLayout(g)

        self._fill_presets()
        self.preset.activated.connect(self._preset_chosen)

        row = QHBoxLayout()
        self.btn_check = QPushButton("Проверить YouTube")
        self.btn_check.clicked.connect(self.check_now)
        self.btn_dns = QPushButton("Проверить DNS")
        self.btn_dns.clicked.connect(self.check_dns)
        btn_copy = QPushButton("Копировать адрес")
        btn_copy.clicked.connect(lambda: self._copy(self._socks_url(), "Адрес SOCKS скопирован"))
        btn_browser = QPushButton("Браузер")
        btn_browser.setToolTip(
            "Запускает браузер через прокси (команда browser_cmd в конфиге).\n"
            "Флаг --proxy-server работает, только если Chromium ещё не открыт.\n"
            "Firefox: Настройки → Параметры сети → SOCKS v5, 127.0.0.1, порт,\n"
            "и галка «Отправлять DNS-запросы через прокси».")
        btn_browser.clicked.connect(self.launch_browser)
        for b in (self.btn_check, self.btn_dns, btn_copy, btn_browser):
            row.addWidget(b)
        row.addStretch()
        c.lay.addLayout(row)
        return c

    def _build_tg_card(self) -> Card:
        c = Card("Telegram · tg-ws-proxy")
        self.card_tg = c
        c.toggle.toggled.connect(lambda on: self.start_tg() if on else self.stop_tg())

        g = QGridLayout()
        g.setHorizontalSpacing(8)
        g.addWidget(QLabel("Порт"), 0, 0)
        self.tg_port = QSpinBox()
        self.tg_port.setRange(1024, 65535)
        self.tg_port.setValue(self.cfg["tg_port"])
        g.addWidget(self.tg_port, 0, 1)
        g.addWidget(QLabel("Secret"), 0, 2)
        self.tg_secret = QLineEdit(self.cfg["tg_secret"])
        self.tg_secret.setMaxLength(32)
        self.tg_secret.setFont(QFont("monospace", 9))
        g.addWidget(self.tg_secret, 0, 3)
        btn_regen = QPushButton("↻")
        btn_regen.setToolTip("Сгенерировать новый secret")
        btn_regen.setFixedWidth(34)
        btn_regen.clicked.connect(lambda: self.tg_secret.setText(secrets.token_hex(16)))
        g.addWidget(btn_regen, 0, 4)
        g.addWidget(QLabel("Доп. флаги"), 1, 0)
        self.tg_extra = QLineEdit(self.cfg["tg_extra_args"])
        self.tg_extra.setPlaceholderText("напр. --dc-ip 4:149.154.167.220  или  --no-cfproxy")
        g.addWidget(self.tg_extra, 1, 1, 1, 4)
        g.setColumnStretch(3, 1)
        c.lay.addLayout(g)

        row = QHBoxLayout()
        btn_open = QPushButton("Применить в Telegram")
        btn_open.setObjectName("accent")
        btn_open.clicked.connect(self.open_in_telegram)
        btn_link = QPushButton("Копировать ссылку")
        btn_link.clicked.connect(lambda: self._copy(self._tg_link("https://t.me/proxy"),
                                                    "Ссылка на прокси скопирована"))
        row.addWidget(btn_open)
        row.addWidget(btn_link)
        row.addStretch()
        c.lay.addLayout(row)
        return c

    def _build_test_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.btn_test = QPushButton("Подобрать стратегию")
        self.btn_test.setObjectName("accent")
        self.btn_test.clicked.connect(self.run_tester)
        self.btn_apply = QPushButton("Применить выбранную")
        self.btn_apply.clicked.connect(self._apply_selected)
        self.btn_update = QPushButton("Обновить список")
        self.btn_update.setToolTip("Скачать свежий список стратегий из ByeByeDPI (romanvht) на GitHub")
        self.btn_update.clicked.connect(self.update_strategies)
        top.addWidget(self.btn_test)
        top.addWidget(self.btn_apply)
        top.addStretch()
        top.addWidget(self.btn_update)
        lay.addLayout(top)

        self.test_info = QLabel()
        self.test_info.setObjectName("hint")
        self.test_info.setWordWrap(True)
        lay.addWidget(self.test_info)
        self.test_bar = QProgressBar()
        self.test_bar.setTextVisible(True)
        self.test_bar.hide()
        lay.addWidget(self.test_bar)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Сайтов", "Стратегия"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFont(QFont("monospace", 9))
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(lambda _: self._apply_selected())
        lay.addWidget(self.table, 1)
        self._update_test_info()
        return w

    def _build_tray(self):
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(tray_icon(False, False), self)
        self.tray.setToolTip(APP_NAME)
        m = QMenu()
        self.act_dpi = QAction("Сайты", m, checkable=True)
        self.act_tg = QAction("Telegram", m, checkable=True)
        self.act_dpi.triggered.connect(lambda on: self.start_dpi() if on else self.stop_dpi())
        self.act_tg.triggered.connect(lambda on: self.start_tg() if on else self.stop_tg())
        m.addAction(self.act_dpi)
        m.addAction(self.act_tg)
        m.addSeparator()
        m.addAction("Применить в Telegram", self.open_in_telegram)
        m.addAction("Показать окно", self._show)
        m.addSeparator()
        m.addAction("Выход", self.quit_app)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(
            lambda r: self._toggle_window() if r == QSystemTrayIcon.Trigger else None)
        self.tray.show()

    # ---------- helpers ----------

    def _check_install(self):
        missing = []
        if not CIADPI.exists():
            missing.append(f"byedpi: {CIADPI}")
        if not (TGWS_DIR / "proxy" / "tg_ws_proxy.py").exists():
            missing.append(f"tg-ws-proxy: {TGWS_DIR}")
        if not shutil.which("curl"):
            missing.append("curl (нужен для проверок)")
        if missing:
            QMessageBox.warning(self, APP_NAME,
                                "Не найдено:\n\n" + "\n".join(missing) +
                                "\n\nЗапусти install.sh из папки проекта.")

    def _python(self) -> str:
        return str(VENV_PY) if VENV_PY.exists() else sys.executable

    def _socks_url(self) -> str:
        return f"socks5://127.0.0.1:{self.dpi_port.value()}"

    def _tg_link(self, base: str = "tg://proxy") -> str:
        return (f"{base}?server=127.0.0.1&port={self.tg_port.value()}"
                f"&secret=dd{self.tg_secret.text().strip()}")

    def _copy(self, text: str, msg: str):
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage(msg, 3000)

    def _sites(self) -> list[str]:
        return list(self.cfg.get("test_sites") or DEFAULT_TEST_SITES)

    def _update_test_info(self):
        self.test_info.setText(
            f"В списке {len(load_strategies())} стратегий из ByeByeDPI. Каждая проверяется на "
            f"{len(self._sites())} адресах YouTube; сайт засчитывается, только если ответ "
            f"скачался целиком (так ловится обрыв на ~16 КБ). Займёт несколько минут. "
            f"Двойной клик по строке — применить.")

    def _fill_presets(self):
        """Комбобокс: лучшие из прошлого подбора + «свои аргументы»."""
        self.preset.clear()
        for score, total, args in self.cfg.get("favorites", []):
            self.preset.addItem(f"{score}/{total} · {args}", args)
        self.preset.addItem("Свои аргументы", None)
        args = self.dpi_args.text().strip()
        idx = self.preset.findData(args)
        self.preset.setCurrentIndex(idx if idx >= 0 else self.preset.count() - 1)

    def _set_args(self, args: str):
        self.dpi_args.setText(args)
        self.dpi_args.setCursorPosition(0)

    def _preset_chosen(self, idx: int):
        args = self.preset.itemData(idx)
        if args:
            self._set_args(args)
        else:
            self.dpi_args.setFocus()

    def _save(self):
        self.cfg.update(
            byedpi_port=self.dpi_port.value(),
            byedpi_args=self.dpi_args.text().strip(),
            fake_sni=self.fake_sni.text().strip() or "google.com",
            tg_port=self.tg_port.value(),
            tg_secret=self.tg_secret.text().strip(),
            tg_extra_args=self.tg_extra.text().strip(),
        )
        save_cfg(self.cfg)

    def _save_opts(self):
        self.cfg.update(autostart_byedpi=self.cb_auto_dpi.isChecked(),
                        autostart_tg=self.cb_auto_tg.isChecked(),
                        start_hidden=self.cb_hidden.isChecked())
        save_cfg(self.cfg)

    def _log(self, which: str, text: str):
        view = {"dpi": self.log_dpi, "tg": self.log_tg}[which]
        view.appendPlainText(text.rstrip("\n"))

    def _bg(self, fn, on_done):
        w = Worker(fn)
        w.finished_with.connect(on_done)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _refresh_tray(self):
        on_d = self.p_dpi.state() != QProcess.NotRunning
        on_t = self.p_tg.state() != QProcess.NotRunning
        if self.tray:
            self.tray.setIcon(tray_icon(on_d, on_t))
            self.act_dpi.setChecked(on_d)
            self.act_tg.setChecked(on_t)
            self.tray.setToolTip(f"{APP_NAME}\nСайты: {'вкл' if on_d else 'выкл'}"
                                 f"\nTelegram: {'вкл' if on_t else 'выкл'}")
        for w in (self.dpi_port, self.dpi_args, self.preset, self.fake_sni):
            w.setEnabled(not on_d)
        for w in (self.tg_port, self.tg_secret, self.tg_extra):
            w.setEnabled(not on_t)

    # ---------- процессы ----------

    def start_dpi(self):
        if self.p_dpi.state() != QProcess.NotRunning:
            return
        self._save()
        port = self.dpi_port.value()
        if port_busy(port):
            self.card_dpi.set_state("err", f"Порт {port} уже занят")
            return
        try:
            extra = expand_args(self.dpi_args.text(), self.fake_sni.text().strip())
        except ValueError as e:
            self.card_dpi.set_state("err", f"Аргументы: {e}")
            return
        args = ["-i", "127.0.0.1", "-p", str(port), *extra]
        self._log("dpi", f"$ ciadpi {' '.join(args)}")
        self.card_dpi.set_state("wait")
        self.p_dpi.start(str(CIADPI), args)

    def stop_dpi(self):
        self._stop_proc(self.p_dpi)

    def start_tg(self):
        if self.p_tg.state() != QProcess.NotRunning:
            return
        secret = self.tg_secret.text().strip()
        try:
            ok = len(secret) == 32 and bytes.fromhex(secret)
        except ValueError:
            ok = False
        if not ok:
            self.card_tg.set_state("err", "Secret: нужно 32 hex-символа")
            return
        self._save()
        port = self.tg_port.value()
        if port_busy(port):
            self.card_tg.set_state("err", f"Порт {port} уже занят")
            return
        try:
            extra = shlex.split(self.tg_extra.text())
        except ValueError as e:
            self.card_tg.set_state("err", f"Флаги: {e}")
            return
        args = ["-u", "-m", "proxy.tg_ws_proxy", "--host", "127.0.0.1",
                "--port", str(port), "--secret", secret, *extra]
        self.p_tg.setWorkingDirectory(str(TGWS_DIR))
        self._log("tg", "$ python " + " ".join(args).replace(secret, secret[:4] + "…"))
        self.card_tg.set_state("wait")
        self.p_tg.start(self._python(), args)

    def stop_tg(self):
        self._stop_proc(self.p_tg)

    def _stop_proc(self, proc: QProcess):
        if proc.state() == QProcess.NotRunning:
            return
        self._user_stopped.add(id(proc))
        proc.terminate()
        if not proc.waitForFinished(2500):
            proc.kill()
            proc.waitForFinished(1000)

    def _read(self, proc: QProcess, name: str):
        data = bytes(proc.readAllStandardOutput()).decode("utf-8", "replace")
        self._log(name, data)

    def _started(self, name: str):
        card = self.card_dpi if name == "dpi" else self.card_tg
        port = self.dpi_port.value() if name == "dpi" else self.tg_port.value()
        proc = self.p_dpi if name == "dpi" else self.p_tg
        tries = [0]

        # «работает» — когда порт реально начал слушать
        def probe():
            if proc.state() == QProcess.NotRunning:
                return
            if port_busy(port):
                card.set_state("on", f"Работает · 127.0.0.1:{port}")
                self._refresh_tray()
            elif tries[0] < 50:
                tries[0] += 1
                QTimer.singleShot(100, probe)
            else:
                card.set_state("err", "Процесс запущен, но порт не слушает")
        QTimer.singleShot(100, probe)
        self._refresh_tray()

    def _finished(self, name: str, code: int, status):
        card = self.card_dpi if name == "dpi" else self.card_tg
        proc = self.p_dpi if name == "dpi" else self.p_tg
        if self.quitting:
            return
        stopped_by_us = id(proc) in self._user_stopped
        self._user_stopped.discard(id(proc))
        if stopped_by_us or (status == QProcess.NormalExit and code == 0):
            card.set_state("off")
        else:
            card.set_state("err", f"Упал (код {code}) — смотри лог")
        self._log(name, f"— процесс завершён (код {code})")
        self._refresh_tray()

    def _error(self, name: str, err):
        if err == QProcess.FailedToStart:
            card = self.card_dpi if name == "dpi" else self.card_tg
            card.set_state("err", "Не удалось запустить — проверь установку")
            self._log(name, "Не удалось запустить процесс. Запусти install.sh.")
            self._refresh_tray()

    # ---------- действия ----------

    def open_in_telegram(self):
        if self.p_tg.state() == QProcess.NotRunning:
            self.start_tg()
        if not QProcess.startDetached("xdg-open", [self._tg_link()]):
            self._copy(self._tg_link("https://t.me/proxy"),
                       "xdg-open не сработал — ссылка скопирована, отправь её себе в Избранное")

    def launch_browser(self):
        if self.p_dpi.state() == QProcess.NotRunning:
            self.start_dpi()
        cmd = self.cfg.get("browser_cmd", DEFAULT_CFG["browser_cmd"]).format(
            port=self.dpi_port.value())
        parts = shlex.split(cmd)
        if not parts or not shutil.which(parts[0]):
            QMessageBox.information(
                self, APP_NAME,
                f"Не найден браузер «{parts[0] if parts else ''}».\n\n"
                f"Поменяй команду в {CFG_FILE} (ключ browser_cmd), например:\n"
                "  brave-browser --proxy-server=socks5://127.0.0.1:{port}\n\n"
                "Или пропиши прокси в браузере вручную: SOCKS5, 127.0.0.1, "
                f"порт {self.dpi_port.value()}.")
            return
        QProcess.startDetached(parts[0], parts[1:])

    def check_now(self):
        if self.p_dpi.state() == QProcess.NotRunning:
            self.statusBar().showMessage("Сначала запусти byedpi", 3000)
            return
        self.btn_check.setEnabled(False)
        sites = self._sites()
        port, t = self.dpi_port.value(), int(self.cfg.get("test_timeout", 5))
        self.statusBar().showMessage(f"Проверяю {len(sites)} адресов YouTube через прокси…")

        def done(ok):
            self.btn_check.setEnabled(True)
            verdict = "работает ✓" if ok == len(sites) else (
                "частично — видео может тормозить" if ok else "не работает ✗")
            self.statusBar().showMessage(f"YouTube: {ok}/{len(sites)} — {verdict}", 10000)
        self._bg(lambda: check_sites(port, sites, t), done)

    # ---------- подбор стратегий ----------

    def run_tester(self):
        if self.tester and self.tester.isRunning():
            self.tester.stop()
            self.btn_test.setText("Останавливаю…")
            self.btn_test.setEnabled(False)
            return
        if not shutil.which("curl"):
            QMessageBox.warning(self, APP_NAME, "Нужен curl: sudo xbps-install curl")
            return
        self._save()
        strategies = load_strategies()
        own = self.dpi_args.text().strip()
        if own and own not in strategies:
            strategies.insert(0, own)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.test_bar.setRange(0, len(strategies))
        self.test_bar.setValue(0)
        self.test_bar.show()
        self.tester = StrategyTester(strategies, self._sites(), self.fake_sni.text().strip(),
                                     int(self.cfg.get("test_timeout", 5)))
        self.tester.progress.connect(
            lambda i, n, a: (self.test_bar.setValue(i),
                             self.test_bar.setFormat(f"{i + 1}/{n}  {a[:60]}")))
        self.tester.result.connect(self._test_result)
        self.tester.failed.connect(lambda m: QMessageBox.warning(self, APP_NAME, m))
        self.tester.done.connect(self._test_done)
        self.btn_test.setText("Остановить подбор")
        self.btn_update.setEnabled(False)
        self.tabs.setCurrentIndex(0)
        self.tester.start()

    def _test_result(self, args: str, ok: int, total: int):
        r = self.table.rowCount()
        self.table.insertRow(r)
        score = QTableWidgetItem()
        score.setData(Qt.DisplayRole, ok)
        score.setData(Qt.UserRole, total)
        score.setTextAlignment(Qt.AlignCenter)
        color = "#3ddc84" if ok == total else ("#ffb74d" if ok else "#ef5350")
        score.setForeground(QColor(color))
        self.table.setItem(r, 0, score)
        self.table.setItem(r, 1, QTableWidgetItem(args))

    def _test_done(self, stopped: bool):
        self.btn_test.setText("Подобрать стратегию")
        self.btn_test.setEnabled(True)
        self.btn_update.setEnabled(True)
        self.test_bar.hide()
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.DescendingOrder)

        rows = [(self.table.item(r, 0).data(Qt.DisplayRole),
                 self.table.item(r, 0).data(Qt.UserRole),
                 self.table.item(r, 1).text()) for r in range(self.table.rowCount())]
        rows = [r for r in rows if r[0] > 0]
        rows.sort(key=lambda r: (-r[0], len(r[2])))   # при равенстве — короче проще
        if not rows:
            self.statusBar().showMessage(
                "Ни одна стратегия не прошла. Нажми «Проверить DNS» — возможно, дело не в DPI.", 15000)
            return
        self.cfg["favorites"] = [list(r) for r in rows[:8]]
        best = rows[0]
        self._set_args(best[2])
        self._fill_presets()
        self._save()
        for r in range(self.table.rowCount()):
            if self.table.item(r, 1).text() == best[2]:
                self.table.selectRow(r)
                break
        self.statusBar().showMessage(f"Лучшая: {best[0]}/{best[1]} — применена. "
                                     f"Перезапусти byedpi, если он был включён.", 15000)

    def _apply_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        args = self.table.item(rows[0].row(), 1).text()
        was_on = self.p_dpi.state() != QProcess.NotRunning
        if was_on:
            self.stop_dpi()
        self._set_args(args)
        self._fill_presets()
        self._save()
        if was_on:
            QTimer.singleShot(300, self.start_dpi)
        self.statusBar().showMessage("Стратегия применена", 4000)

    def update_strategies(self):
        self.btn_update.setEnabled(False)
        port = self.dpi_port.value() if self.p_dpi.state() != QProcess.NotRunning else None

        def fetch():
            for via in [None] + ([port] if port else []):
                cmd = ["curl", "-sfL", "-m", "15", STRATEGIES_URL]
                if via:
                    cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{via}"]
                try:
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
                except (OSError, subprocess.TimeoutExpired):
                    continue
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                if len(lines) >= 5 and all(l.startswith("-") for l in lines):
                    return lines
            return None

        def done(lines):
            self.btn_update.setEnabled(True)
            if not lines:
                QMessageBox.warning(self, APP_NAME, "Не удалось скачать список с GitHub.")
                return
            CFG_DIR.mkdir(parents=True, exist_ok=True)
            USER_STRATEGIES.write_text("\n".join(lines) + "\n")
            self._update_test_info()
            self.statusBar().showMessage(f"Список обновлён: {len(lines)} стратегий", 6000)
        self._bg(fetch, done)

    # ---------- DNS ----------

    def check_dns(self):
        self.btn_dns.setEnabled(False)
        self.statusBar().showMessage("Проверяю DNS…")
        port = self.dpi_port.value() if self.p_dpi.state() != QProcess.NotRunning else None

        def run():
            res = []
            for h in DNS_TEST_HOSTS:
                res.append((h, system_resolve(h), doh_resolve(h, port)))
            return res

        self._bg(run, self._dns_done)

    def _dns_done(self, res):
        self.btn_dns.setEnabled(True)
        self.statusBar().clearMessage()
        lines, bad = [], False
        for host, sys_ips, doh_ips in res:
            if not sys_ips:
                verdict, bad = "✗ системный DNS не отдаёт адрес", True
            elif not any(is_google_ip(ip) for ip in sys_ips):
                verdict, bad = "✗ адрес не принадлежит Google — похоже на подмену", True
            else:
                verdict = "✓ норм"
            lines.append(f"<b>{host}</b><br>&nbsp;&nbsp;система: {', '.join(sys_ips[:3]) or '—'}"
                         f"<br>&nbsp;&nbsp;DoH: {', '.join(doh_ips[:3]) or 'не ответил'}"
                         f"<br>&nbsp;&nbsp;{verdict}")
        if bad:
            summary = ("<p><b>Проблема в DNS, а не в стратегии.</b> byedpi спрашивает адреса у "
                       "системного резолвера — если он врёт, никакая стратегия не поможет.</p>"
                       "<p>Решение для Void — локальный шифрованный DNS:<br>"
                       "<code>sudo xbps-install dnscrypt-proxy<br>"
                       "sudo ln -s /etc/sv/dnscrypt-proxy /var/service/</code><br>"
                       "и в <code>/etc/resolv.conf</code> оставить <code>nameserver 127.0.0.1</code>. "
                       "Подробнее — в README.</p>")
        else:
            summary = ("<p><b>DNS в порядке</b> — дело в DPI. Запусти «Подобрать стратегию».</p>")
        box = QMessageBox(self)
        box.setWindowTitle("Проверка DNS")
        box.setTextFormat(Qt.RichText)
        box.setText(summary + "<br>".join(lines))
        box.exec()

    # ---------- окно / выход ----------

    def _show(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _toggle_window(self):
        self.hide() if self.isVisible() else self._show()

    def closeEvent(self, e):
        if self.tray and not self.quitting:
            e.ignore()
            self.hide()
            self.tray.showMessage(APP_NAME, "Работаю в трее. Выход — через меню иконки.",
                                  QSystemTrayIcon.Information, 2500)
        else:
            self.quit_app()
            e.accept()

    def quit_app(self):
        self.quitting = True
        self._save()
        if self.tester and self.tester.isRunning():
            self.tester.stop()
            self.tester.wait(20000)
        for w in list(self._workers):
            w.wait(10000)
        self.stop_dpi()
        self.stop_tg()
        QApplication.quit()


STYLE = """
QWidget { font-size: 10pt; }
#card { background: palette(alternate-base); border-radius: 12px; }
#cardTitle { font-weight: 600; font-size: 11pt; }
#status, #hint { color: palette(placeholder-text); }
QPushButton { padding: 6px 12px; border-radius: 8px; background: palette(button); }
QPushButton:hover { background: palette(mid); }
QPushButton:disabled { color: palette(placeholder-text); }
QPushButton#toggle:checked { background: #2e7d32; color: white; }
QPushButton#accent { background: #2aa3e6; color: white; }
QLineEdit, QSpinBox, QComboBox { padding: 4px 6px; border-radius: 6px; }
QPlainTextEdit, QTableWidget { border-radius: 8px; }
QProgressBar { border-radius: 6px; text-align: center; height: 18px; }
QProgressBar::chunk { background: #2aa3e6; border-radius: 6px; }
"""


def dark_palette() -> QPalette:
    p = QPalette()
    base, alt, text = QColor("#1b1d22"), QColor("#262930"), QColor("#e6e6e6")
    p.setColor(QPalette.Window, base)
    p.setColor(QPalette.WindowText, text)
    p.setColor(QPalette.Base, QColor("#15171b"))
    p.setColor(QPalette.AlternateBase, alt)
    p.setColor(QPalette.Text, text)
    p.setColor(QPalette.Button, QColor("#30343c"))
    p.setColor(QPalette.ButtonText, text)
    p.setColor(QPalette.Mid, QColor("#3a3f48"))
    p.setColor(QPalette.Highlight, QColor("#2aa3e6"))
    p.setColor(QPalette.HighlightedText, QColor("white"))
    p.setColor(QPalette.ToolTipBase, alt)
    p.setColor(QPalette.ToolTipText, text)
    p.setColor(QPalette.PlaceholderText, QColor("#8a8f99"))
    for role in (QPalette.Text, QPalette.ButtonText, QPalette.WindowText):
        p.setColor(QPalette.Disabled, role, QColor("#6b7079"))
    return p


def main():
    QApplication.setApplicationName("byedpi-tg")
    QApplication.setDesktopFileName("byedpi-tg")
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyle("Fusion")
    if os.environ.get("BYEDPI_TG_LIGHT") != "1":
        app.setPalette(dark_palette())
    app.setStyleSheet(STYLE)
    app.setWindowIcon(tray_icon(True, True))

    w = MainWindow()
    signal.signal(signal.SIGINT, lambda *_: w.quit_app())
    signal.signal(signal.SIGTERM, lambda *_: w.quit_app())
    # чтобы Python успевал обработать сигнал внутри цикла Qt
    t = QTimer()
    t.timeout.connect(lambda: None)
    t.start(300)

    if not (w.cfg["start_hidden"] and w.tray) or "--show" in sys.argv:
        w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
