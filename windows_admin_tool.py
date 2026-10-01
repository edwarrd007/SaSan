import sys
import os
import re
import csv
import json
import base64
import socket
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import quote, unquote, quote_plus, unquote_plus, urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from PySide6.QtCore import QTimer, Qt, QObject, Signal, Slot, QThread, QUrl, QProcess
from PySide6.QtGui import QFont, QDesktopServices, QIcon, QPixmap
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QGridLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QSlider,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
    QWidget, QHeaderView, QListWidget, QListWidgetItem, QProgressBar,
    QScrollArea, QFileDialog
)

try:
    import winreg
except ImportError:
    winreg = None

APP_NAME = "SaSaN Security Tool"
BASE_DIR = Path(__file__).resolve().parent
MUSIC_JSON = BASE_DIR / "music_library.json"
COMMANDS_JSON = BASE_DIR / "tool_commands.json"
PAYLOADS_JSON = BASE_DIR / "payloads.json"

CITIES = [
    ("Tehran", "Asia/Tehran"), ("London", "Europe/London"),
    ("Paris", "Europe/Paris"), ("Berlin", "Europe/Berlin"),
    ("Istanbul", "Europe/Istanbul"), ("Moscow", "Europe/Moscow"),
    ("Dubai", "Asia/Dubai"), ("Riyadh", "Asia/Riyadh"),
    ("New Delhi", "Asia/Kolkata"), ("Beijing", "Asia/Shanghai"),
    ("Tokyo", "Asia/Tokyo"), ("Seoul", "Asia/Seoul"),
    ("Singapore", "Asia/Singapore"), ("Bangkok", "Asia/Bangkok"),
    ("Jakarta", "Asia/Jakarta"), ("Sydney", "Australia/Sydney"),
    ("Cairo", "Africa/Cairo"), ("Johannesburg", "Africa/Johannesburg"),
    ("New York", "America/New_York"), ("Los Angeles", "America/Los_Angeles"),
]

MUSIC_EXTENSIONS = {".mp3"}


def now_in_zone(zone_name: str) -> datetime:
    try:
        return datetime.now(ZoneInfo(zone_name))
    except ZoneInfoNotFoundError:
        return datetime.now()


def qitem(value: str, align=Qt.AlignLeft | Qt.AlignVCenter) -> QTableWidgetItem:
    item = QTableWidgetItem(str(value))
    item.setTextAlignment(align)
    return item


def local_ipv4() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def run_command(command: str, timeout: int = 30) -> tuple[bool, str, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=flags,
        )
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out."
    except Exception as exc:
        return False, "", str(exc)


# -----------------------------------------------------------------------------
# Proxy
# -----------------------------------------------------------------------------
class ProxyManager:
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    @staticmethod
    def get_proxy() -> dict:
        result = {"enabled": False, "server": "", "auto_config": "", "bypass": ""}
        if winreg is None:
            return result
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ProxyManager.KEY) as key:
                try:
                    result["enabled"] = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
                except FileNotFoundError:
                    pass
                for src, dst in (("ProxyServer", "server"), ("AutoConfigURL", "auto_config"), ("ProxyOverride", "bypass")):
                    try:
                        result[dst] = str(winreg.QueryValueEx(key, src)[0])
                    except FileNotFoundError:
                        pass
        except OSError:
            pass
        return result

    @staticmethod
    def set_proxy(enabled: bool, server: str | None = None) -> None:
        if winreg is None:
            raise RuntimeError("Proxy settings are available on Windows only.")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, ProxyManager.KEY) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enabled else 0)
            if server is not None:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        # Notify WinINet that Internet Settings changed.
        try:
            import ctypes
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            wininet = ctypes.windll.Wininet
            wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Fast Windows listening ports
# -----------------------------------------------------------------------------
class PortScannerWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    @staticmethod
    def _parse_netstat(text: str, protocol: str):
        rows = []
        for line in text.splitlines():
            parts = line.split()
            if not parts or parts[0].upper() != protocol:
                continue
            try:
                if protocol == "TCP":
                    if len(parts) < 5 or parts[-2].upper() != "LISTENING":
                        continue
                    local = parts[1]
                    port = local.rsplit(":", 1)[-1]
                    pid = parts[-1]
                else:
                    if len(parts) < 4:
                        continue
                    local = parts[1]
                    port = local.rsplit(":", 1)[-1]
                    pid = parts[-1]
                if not port.isdigit() or not pid.isdigit():
                    continue
                address = local[: -(len(port) + 1)] if local.endswith(":" + port) else local
                rows.append((protocol, address, port, pid))
            except Exception:
                continue
        return rows

    @staticmethod
    def _process_map() -> dict[str, str]:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=flags,
        )
        result = {}
        for row in csv.reader(proc.stdout.splitlines()):
            if len(row) >= 2 and row[1].isdigit():
                result[row[1]] = row[0]
        return result

    def run(self):
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            tcp = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=8, creationflags=flags
            )
            udp = subprocess.run(
                ["netstat", "-ano", "-p", "udp"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=8, creationflags=flags
            )
            if tcp.returncode != 0 and udp.returncode != 0:
                raise RuntimeError("netstat could not read network endpoints.")

            entries = self._parse_netstat(tcp.stdout, "TCP") + self._parse_netstat(udp.stdout, "UDP")
            pmap = self._process_map()
            rows = [(proto, addr, port, pid, pmap.get(pid, "Unknown")) for proto, addr, port, pid in entries]
            rows.sort(key=lambda r: (r[0], int(r[2]), r[1]))
            self.finished.emit(rows)
        except Exception as exc:
            self.failed.emit(str(exc))


# -----------------------------------------------------------------------------
# Music scanner
# -----------------------------------------------------------------------------
class MusicScanWorker(QObject):
    found = Signal(str)
    progress = Signal(str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, root: Path):
        super().__init__()
        self.root = Path(root)

    def run(self):
        found = []
        seen = set()
        try:
            root = self.root
            self.progress.emit(f"Scanning {root} …")
            for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
                dirs[:] = [d for d in dirs if d not in {"$Recycle.Bin", "System Volume Information"}]
                for filename in files:
                    path = Path(current) / filename
                    if path.suffix.lower() in MUSIC_EXTENSIONS:
                        key = str(path).casefold()
                        if key in seen:
                            continue
                        seen.add(key)
                        value = str(path)
                        found.append(value)
                        if len(found) % 10 == 0:
                            self.progress.emit(f"Found {len(found)} tracks …")
                        self.found.emit(value)
            self.finished.emit(found)
        except Exception as exc:
            self.failed.emit(str(exc))


# -----------------------------------------------------------------------------
# Security helpers
# -----------------------------------------------------------------------------
class JSFuckEncoder:
    """Python port of JSFuck 0.5.0 encoder."""

    MIN = 32
    MAX = 126

    SIMPLE = {
        "false": "![]",
        "true": "!![]",
        "undefined": "[][[]]",
        "NaN": "+[![]]",
        "Infinity": "+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]]+[+[]])",
    }

    CONSTRUCTORS = {
        "Array": "[]",
        "Number": "(+[])",
        "String": "([]+[])",
        "Boolean": "(![])",
        "Function": '[]["at"]',
        "RegExp": 'Function("return/"+false+"/")()',
    }

    MAPPING = {
        "a": '(false+"")[1]',
        "b": '([]["entries"]()+"")[2]',
        "c": '([]["at"]+"")[3]',
        "d": '(undefined+"")[2]',
        "e": '(true+"")[3]',
        "f": '(false+"")[0]',
        "g": '(false+[0]+String)[20]',
        "h": '(+(101))["to"+String["name"]](21)[1]',
        "i": '([false]+undefined)[10]',
        "j": '([]["entries"]()+"")[3]',
        "k": '(+(20))["to"+String["name"]](21)',
        "l": '(false+"")[2]',
        "m": '(Number+"")[11]',
        "n": '(undefined+"")[1]',
        "o": '(true+[]["at"])[10]',
        "p": '(+(211))["to"+String["name"]](31)[1]',
        "q": '"")["fontcolor"]([0]+false+")[20]',
        "r": '(true+"")[1]',
        "s": '(false+"")[3]',
        "t": '(true+"")[0]',
        "u": '(undefined+"")[0]',
        "v": '(+(31))["to"+String["name"]](32)',
        "w": '(+(32))["to"+String["name"]](33)',
        "x": '(+(101))["to"+String["name"]](34)[1]',
        "y": '(NaN+[Infinity])[10]',
        "z": '(+(35))["to"+String["name"]](36)',

        "A": '(NaN+[]["entries"]())[11]',
        "B": '(+[]+Boolean)[10]',
        "C": 'Function("return escape")()(("")["italics"]())[2]',
        "D": 'Function("return escape")()([]["at"])["at"]("-1")',
        "E": '(RegExp+"")[12]',
        "F": '(+[]+Function)[10]',
        "G": '(false+Function("return Date")()())[30]',
        "H": None,
        "I": '(Infinity+"")[0]',
        "J": None,
        "K": None,
        "L": None,
        "M": '(true+Function("return Date")()())[30]',
        "N": '(NaN+"")[0]',
        "O": None,
        "P": None,
        "Q": None,
        "R": '(+[]+RegExp)[10]',
        "S": '(+[]+String)[10]',
        "T": '(NaN+Function("return Date")()())[30]',
        "U": None,
        "V": None,
        "W": None,
        "X": None,
        "Y": None,
        "Z": None,

        " ": '(NaN+[]["at"])[11]',
        "!": None,
        '"': '("")["fontcolor"]()[12]',
        "#": None,
        "$": None,
        "%": 'Function("return escape")()([]["at"])[22]',
        "&": '("")["fontcolor"](")[13]',
        "'": None,
        "(": '([]["at"]+"")[11]',
        ")": '(""+[]["at"])[12]',
        "*": None,
        "+": '(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]])+[])[2]',
        ",": '[[]]["concat"]([[]])+""',
        "-": '(+(.+[0000001])+"")[2]',
        ".": '(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]',
        "/": '(false+[0])["italics"]()[10]',
        ":": '(RegExp()+"")[3]',
        ";": '("")["fontcolor"](NaN+")[21]',
        "<": '("")["italics"]()[0]',
        "=": '("")["fontcolor"]()[11]',
        ">": '("")["italics"]()[2]',
        "?": '(RegExp()+"")[2]',
        "@": None,
        "[": '([]["entries"]()+"")[0]',
        "\\": '(RegExp("/")+"")[1]',
        "]": '([]["entries"]()+"")[22]',
        "^": None,
        "_": None,
        "`": None,
        "{": '([0]+false+[]["at"])[20]',
        "|": None,
        "}": '([]["at"]+"")["at"]("-1")',
        "~": None,
    }

    GLOBAL = 'Function("return this")()'

    _compiled_mapping = None

    @classmethod
    def _fill_missing_digits(cls, mapping):
        for number in range(10):
            output = "+[]"

            if number > 0:
                output = "+!" + output

            for _ in range(1, number):
                output = "+!+[]" + output

            if number > 1:
                output = output[1:]

            mapping[str(number)] = "[" + output + "]"

    @classmethod
    def _build_mapping(cls):
        if cls._compiled_mapping is not None:
            return dict(cls._compiled_mapping)

        mapping = dict(cls.MAPPING)

        cls._fill_missing_digits(mapping)

        def replace(value, pattern, replacement):
            return re.sub(
                pattern,
                replacement,
                value,
                flags=re.IGNORECASE,
            )

        def digit_replacer(match):
            return mapping[match.group(1)]

        def number_replacer(match):
            values = list(match.group(1))

            head = int(values.pop(0))

            output = "+[]"

            if head > 0:
                output = "+!" + output

            for _ in range(1, head):
                output = "+!+[]" + output

            if head > 1:
                output = output[1:]

            raw = "+".join([output] + values)

            return re.sub(
                r"(\d)",
                digit_replacer,
                raw,
            )

        for i in range(cls.MIN, cls.MAX + 1):
            character = chr(i)
            value = mapping.get(character)

            if not value:
                continue

            # Constructors
            for key, replacement in cls.CONSTRUCTORS.items():
                value = replace(
                    value,
                    r"\b" + re.escape(key),
                    replacement + '["constructor"]',
                )

            # Simple values
            for key, replacement in cls.SIMPLE.items():
                value = replace(
                    value,
                    re.escape(key),
                    replacement,
                )

            # Numbers
            value = replace(
                value,
                r"(\d\d+)",
                number_replacer,
            )

            value = replace(
                value,
                r"\((\d)\)",
                digit_replacer,
            )

            value = replace(
                value,
                r"\[(\d)\]",
                digit_replacer,
            )

            value = replace(
                value,
                "GLOBAL",
                cls.GLOBAL,
            )

            value = replace(
                value,
                r'\+""',
                "+[]",
            )

            value = replace(
                value,
                '""',
                "[]+[]",
            )

            mapping[character] = value

        non_jsfuck = re.compile(r"[^\[\]\(\)!\+]")

        for key, value in list(mapping.items()):
            if value:
                mapping[key] = re.sub(
                    r'"([^\"]+)"',
                    lambda m: "+".join(m.group(1)),
                    value,
                )

        remaining = cls.MAX - cls.MIN

        while True:
            missing = {
                k: v
                for k, v in mapping.items()
                if v and non_jsfuck.search(v)
            }

            if not missing:
                break

            for key, value in list(missing.items()):

                def value_replacer(match):
                    ch = match.group(0)

                    if ch in missing:
                        return ch

                    return mapping.get(ch, ch)

                mapping[key] = non_jsfuck.sub(
                    value_replacer,
                    value,
                )

                missing[key] = mapping[key]

            if remaining == 0:
                raise RuntimeError(
                    "Could not compile the following chars: "
                    + repr(missing)
                )

            remaining -= 1

        cls._compiled_mapping = dict(mapping)

        return dict(mapping)

    @staticmethod
    def _escape_sequence(character):
        cc = ord(character)

        if cc < 256:
            return "\\" + format(cc, "o")

        cc16 = format(cc, "x")

        return "\\u" + ("0000" + cc16)[-4:]

    @classmethod
    def _escape_sequence_for_replace(cls, character):
        return cls._escape_sequence(character).replace(
            "\\",
            "t",
            1,
        )

    def __init__(self):
        self._char_cache = self._build_mapping()

    def encode(
        self,
        input_text: str,
        wrap_with_eval=False,
        run_in_parent_scope=False,
    ):
        output = []

        if not input_text:
            return "", []

        unmapped_chars = "".join(
            k
            for k, value in self._char_cache.items()
            if value
        )

        escaped = re.escape(unmapped_chars)

        unmappped = re.compile(
            r"[^" + escaped + "]"
        )

        unmapped_characters_count = len(
            unmappped.findall(input_text)
        )

        text = input_text

        if unmapped_characters_count > 1:
            text = re.sub(
                r"[^0123456789.adefilnrsuN]",
                self._escape_sequence_for_replace,
                text,
            )

        elif unmapped_characters_count > 0:
            text = re.sub(
                r'["\\]',
                self._escape_sequence,
                text,
            )

            text = unmappped.sub(
                self._escape_sequence,
                text,
            )

        alternatives = "|".join(
            re.escape(k)
            for k in self.SIMPLE
        )

        token_re = re.compile(
            "(?:" + alternatives + r"|.)"
        )

        def mapping_replacer(match):
            character = match.group(0)

            replacement = self.SIMPLE.get(character)

            if replacement:
                output.append(
                    "(" + replacement + "+[])"
                )

            else:
                replacement = self._char_cache.get(character)

                if replacement:
                    output.append(replacement)

                else:
                    raise ValueError(
                        "Found unmapped character: "
                        + repr(character)
                    )

            return character

        token_re.sub(
            mapping_replacer,
            text,
        )

        result = "+".join(output)

        if re.fullmatch(r"\d", text):
            result += "+[]"

        if unmapped_characters_count > 1:
            result = (
                "("
                + result
                + ")["
                + self.encode("split")[0]
                + "]("
                + self.encode("t")[0]
                + ")["
                + self.encode("join")[0]
                + "]("
                + self.encode("\\")[0]
                + ")"
            )

        if unmapped_characters_count > 0:
            result = (
                "[]["
                + self.encode("at")[0]
                + "]["
                + self.encode("constructor")[0]
                + "]("
                + self.encode('return"')[0]
                + "+"
                + result
                + "+"
                + self.encode('"')[0]
                + ")()"
            )

        if wrap_with_eval:
            if run_in_parent_scope:
                result = (
                    "[]["
                    + self.encode("at")[0]
                    + "]["
                    + self.encode("constructor")[0]
                    + "]("
                    + self.encode("return eval")[0]
                    + ")()("
                    + result
                    + ")"
                )
            else:
                result = (
                    "[]["
                    + self.encode("at")[0]
                    + "]["
                    + self.encode("constructor")[0]
                    + "]("
                    + result
                    + ")()"
                )

        return result, []

class Codec:
    @staticmethod
    def transform(mode: str, text: str) -> str:
        if mode == "URL encode":
            return quote(text, safe="")
        if mode == "URL decode":
            return unquote(text)
        if mode == "URL encode (+)":
            return quote_plus(text, safe="")
        if mode == "URL decode (+)":
            return unquote_plus(text)
        if mode == "Double URL encode":
            return quote(quote(text, safe=""), safe="")
        if mode == "Double URL decode":
            return unquote(unquote(text))
        if mode == "Base64 encode":
            return base64.b64encode(text.encode()).decode()
        if mode == "Base64 decode":
            return base64.b64decode(text + "=" * (-len(text) % 4), validate=False).decode("utf-8", errors="replace")
        if mode == "Base64URL encode":
            return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
        if mode == "Base64URL decode":
            return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", errors="replace")
        if mode == "Hex encode":
            return text.encode().hex()
        if mode == "Hex decode":
            return bytes.fromhex(re.sub(r"\s+", "", text)).decode("utf-8", errors="replace")
        if mode == "Unicode escape encode":
            return text.encode("unicode_escape").decode()
        if mode == "Unicode escape decode":
            return bytes(text, "utf-8").decode("unicode_escape")
        if mode == "HTML entity encode":
            import html
            return html.escape(text, quote=True)
        if mode == "HTML entity decode":
            import html
            return html.unescape(text)
        if mode == "JWT payload decode":
            parts = text.split(".")
            if len(parts) != 3:
                raise ValueError("JWT must contain three dot-separated parts.")
            payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
            return payload.decode("utf-8", errors="replace")
        raise ValueError("Unknown codec.")


class Extractor:
    URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
    EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
    IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}\b", re.I)
    HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})\b", re.I)
    JWT_RE = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
    SECRET_RE = re.compile(r"(?im)^.*\b(?:api[_-]?key|access[_-]?token|secret|authorization|password|passwd|client_secret)\b.*$")

    @staticmethod
    def _uniq(values):
        return list(dict.fromkeys(values))

    @classmethod
    def extract(cls, text: str) -> dict[str, list[str]]:
        urls = cls._uniq([x.rstrip(".,);]}") for x in cls.URL_RE.findall(text)])
        emails = cls._uniq(cls.EMAIL_RE.findall(text))
        ips = []
        for x in cls._uniq(cls.IPV4_RE.findall(text)):
            try:
                if all(0 <= int(p) <= 255 for p in x.split(".")):
                    ips.append(x)
            except Exception:
                pass
        domains = cls._uniq(cls.DOMAIN_RE.findall(text))
        hashes = cls._uniq(cls.HASH_RE.findall(text))
        jwts = cls._uniq(cls.JWT_RE.findall(text))
        secrets = cls._uniq([line.strip() for line in cls.SECRET_RE.findall(text)])
        paths = cls._uniq(re.findall(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)", text))
        return {
            "URLs": urls, "Domains": domains, "IPv4": ips, "Emails": emails,
            "Hashes": hashes, "JWT-like": jwts, "Paths": paths, "Security keyword lines": secrets,
        }


# -----------------------------------------------------------------------------
# Generic command worker
# -----------------------------------------------------------------------------
class CommandWorker(QObject):
    finished = Signal(bool, str, str)

    def __init__(self, command: str, timeout=30):
        super().__init__()
        self.command = command
        self.timeout = timeout

    def run(self):
        ok, out, err = run_command(self.command, self.timeout)
        self.finished.emit(ok, out, err)


# -----------------------------------------------------------------------------
# Main window
# -----------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1380, 900)
        self.setMinimumSize(1100, 720)

        self.port_thread = None
        self.port_worker = None
        self.music_thread = None
        self.music_worker = None
        self.cmd_thread = None
        self.cmd_worker = None
        self.nmap_process = None
        self.nmap_timer = None
        self.current_tracks: list[str] = []
        self._music_scan_seen: set[str] = set()
        self.music_index = -1

        self.jsfuck = JSFuckEncoder()
        self.ensure_json_files()
        self.build_ui()
        self.refresh_proxy()
        self.load_music_library()
        self.refresh_ports()
        self.update_clocks()

        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self.update_selected_clock)
        self.clock_timer.start(1000)

        self.port_timer = QTimer(self)
        self.port_timer.timeout.connect(self.refresh_ports)
        self.port_timer.start(15000)

    # --------------------------- setup ---------------------------
    def ensure_json_files(self):
        if not MUSIC_JSON.exists():
            MUSIC_JSON.write_text(json.dumps({"tracks": []}, ensure_ascii=False, indent=2), encoding="utf-8")
        if not COMMANDS_JSON.exists():
            COMMANDS_JSON.write_text(json.dumps({
                "nslookup": "nslookup {target}",
                "dig": "dig {target}",
            }, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_commands(self) -> dict:
        try:
            data = json.loads(COMMANDS_JSON.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save_commands(self, data: dict):
        COMMANDS_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def build_ui(self):
        self.setStyleSheet(self.theme())
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        header = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(QIcon(str(BASE_DIR / "assets" / "sasan_logo.svg")).pixmap(34, 34))
        logo.setToolTip("SaSaN Security Tool")
        header.addWidget(logo)
        title = QLabel(APP_NAME)
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        header.addWidget(title)
        header.addSpacing(8)
        header.addWidget(QLabel("Clock"))
        self.clock_city = QComboBox()
        self.clock_city.addItems([c for c, _ in CITIES])
        self.clock_city.currentIndexChanged.connect(self.update_selected_clock)
        self.clock_time = QLabel("--:--:--")
        self.clock_date = QLabel("----/--/--")
        self.clock_zone = QLabel("Asia/Tehran")
        header.addWidget(self.clock_city)
        header.addWidget(self.clock_time)
        header.addWidget(self.clock_date)
        header.addWidget(self.clock_zone)
        header.addStretch(1)
        layout.addLayout(header)

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.addTab(self.build_system_page(), QIcon(str(BASE_DIR / "assets/icons/system.svg")), "SYSTEM")
        tabs.addTab(self.build_security_page(), QIcon(str(BASE_DIR / "assets/icons/security.svg")), "SECURITY TOOLKIT")
        tabs.addTab(self.build_payload_page(), QIcon(str(BASE_DIR / "assets/icons/payload.svg")), "CREATE PAYLOAD")
        layout.addWidget(tabs, 1)
        self.setCentralWidget(root)

    def theme(self):
        return """
        QWidget { font-family: Segoe UI; font-size: 10pt; color: #dce8ff; }
        QMainWindow { background: #080b16; }
        QTabWidget::pane { border: 1px solid #25284b; border-radius: 8px; background: #0b0f1e; }
        QTabBar::tab { background: #11162b; color: #7786b7; padding: 7px 16px; margin-right: 2px; border: 1px solid #25284b; border-bottom: 0; border-radius: 7px 7px 0 0; }
        QTabBar::tab:selected { color: #73d5ff; background: #151b35; border-color: #4b4ce7; }
        QGroupBox { border: 1px solid #272b56; border-radius: 8px; margin-top: 9px; padding: 6px; font-weight: 600; color: #a855f7; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
        QLabel { color: #ccd7f5; }
        QLineEdit, QComboBox, QSpinBox, QTextEdit, QListWidget {
            background: #0e1324; color: #dce8ff; border: 1px solid #2b3266; border-radius: 5px; padding: 5px;
            selection-background-color: #4338ca;
        }
        QPushButton { background: #171d3b; color: #dfe9ff; border: 1px solid #3440a2; border-radius: 5px; padding: 5px 10px; }
        QPushButton:hover { background: #20285a; border-color: #6c5ce7; }
        QPushButton:pressed { background: #10152d; }
        QCheckBox { color: #dce8ff; }
        QTableWidget { background: #0c1120; color: #dce8ff; gridline-color: #1e2442; border: 1px solid #272b56; }
        QHeaderView::section { background: #141936; color: #8fdcff; padding: 4px; border: 0; border-bottom: 1px solid #272b56; }
        QSlider::groove:horizontal { height: 4px; background: #262b54; border-radius: 2px; }
        QSlider::handle:horizontal { width: 11px; margin: -4px 0; border-radius: 6px; background: #8b5cf6; }
        QProgressBar { border: 1px solid #272b56; border-radius: 4px; background: #0d1120; color: #9fb1d9; text-align: center; }
        QProgressBar::chunk { background: #5b5cf0; border-radius: 3px; }
        """

    # --------------------------- page 1 ---------------------------
    def build_system_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        proxy = QGroupBox("PROXY")
        pl = QHBoxLayout(proxy)
        pl.setContentsMargins(3, 3, 3, 3)
        pl.setSpacing(5)
        self.proxy_enabled = QCheckBox("ON")
        self.proxy_server = QLineEdit()
        self.proxy_server.setPlaceholderText("Windows proxy server")
        local_btn = QPushButton("LOCAL IP")
        local_btn.setToolTip("Use this Windows host IPv4 with port 8080")
        local_btn.clicked.connect(lambda: self.proxy_server.setText(f"{local_ipv4()}:8080"))
        apply_btn = QPushButton("APPLY")
        apply_btn.clicked.connect(self.apply_proxy)
        off_btn = QPushButton("OFF")
        off_btn.clicked.connect(self.disable_proxy)
        refresh_btn = QPushButton("↻")
        refresh_btn.clicked.connect(self.refresh_proxy)
        pl.addWidget(self.proxy_enabled)
        pl.addWidget(self.proxy_server, 1)
        pl.addWidget(local_btn)
        pl.addWidget(apply_btn)
        pl.addWidget(off_btn)
        pl.addWidget(refresh_btn)

        ports = QGroupBox("OPEN TCP / UDP")
        pol = QVBoxLayout(ports)
        pol.setContentsMargins(3, 3, 3, 3)
        top = QHBoxLayout()
        self.port_status = QLabel("Loading…")
        top.addWidget(self.port_status)
        top.addStretch(1)
        refresh_ports_btn = QPushButton("REFRESH")
        refresh_ports_btn.clicked.connect(self.refresh_ports)
        top.addWidget(refresh_ports_btn)
        pol.addLayout(top)
        self.port_table = QTableWidget(0, 5)
        self.port_table.setHorizontalHeaderLabels(["PROTO", "LOCAL ADDRESS", "PORT", "PID", "PROCESS"])
        self.port_table.verticalHeader().setVisible(False)
        self.port_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.port_table.setMinimumHeight(230)
        self.port_table.setMaximumHeight(260)
        h = self.port_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.Stretch)
        pol.addWidget(self.port_table)

        top_row = QHBoxLayout()
        top_row.setSpacing(6)
        top_row.addWidget(proxy, 1)
        top_row.addWidget(ports, 1)
        layout.addLayout(top_row)

        music = QGroupBox("MUSIC")
        ml = QVBoxLayout(music)
        ml.setContentsMargins(3, 3, 3, 3)
        row = QHBoxLayout()
        self.music_scan_btn = QPushButton("SCAN BASE")
        self.music_scan_btn.setIcon(QIcon(str(BASE_DIR / "assets/icons/music.svg")))
        self.music_scan_btn.setToolTip(f"Scan only the application BASE folder: {BASE_DIR}")
        self.music_scan_btn.clicked.connect(lambda: self.scan_music(BASE_DIR))
        self.music_folder_btn = QPushButton("SCAN FOLDER")
        self.music_folder_btn.setIcon(QIcon(str(BASE_DIR / "assets/icons/folder.svg")))
        self.music_folder_btn.setToolTip("Choose a folder and recursively scan it for music")
        self.music_folder_btn.clicked.connect(self.choose_music_folder)
        reload_btn = QPushButton("RELOAD JSON")
        reload_btn.clicked.connect(self.load_music_library)
        self.music_status = QLabel("0 tracks")
        self.music_progress = QProgressBar()
        self.music_progress.setRange(0, 0)
        self.music_progress.setVisible(False)
        row.addWidget(self.music_scan_btn)
        row.addWidget(self.music_folder_btn)
        row.addWidget(reload_btn)
        row.addWidget(self.music_status)
        row.addWidget(self.music_progress, 1)
        ml.addLayout(row)
        self.music_list = QListWidget()
        self.music_list.setMaximumHeight(145)
        self.music_list.itemDoubleClicked.connect(self.play_selected)
        ml.addWidget(self.music_list)

        controls = QHBoxLayout()
        prev = QPushButton("◀")
        prev.clicked.connect(self.play_previous)
        self.play_btn = QPushButton("PLAY")
        self.play_btn.clicked.connect(self.toggle_play)
        nxt = QPushButton("▶")
        nxt.clicked.connect(self.play_next)
        stop = QPushButton("STOP")
        stop.clicked.connect(self.stop_music)
        self.music_title = QLabel("No track")
        self.music_title.setToolTip(str(MUSIC_JSON))
        self.music_volume = QSlider(Qt.Horizontal)
        self.music_volume.setRange(0, 100)
        self.music_volume.setValue(70)
        controls.addWidget(prev)
        controls.addWidget(self.play_btn)
        controls.addWidget(nxt)
        controls.addWidget(stop)
        controls.addWidget(self.music_title, 1)
        controls.addWidget(QLabel("VOL"))
        controls.addWidget(self.music_volume, 0)
        ml.addLayout(controls)
        layout.addWidget(music)

        self.player = QMediaPlayer(self)
        self.audio = QAudioOutput(self)
        self.player.setAudioOutput(self.audio)
        self.audio.setVolume(0.7)
        self.music_volume.valueChanged.connect(lambda v: self.audio.setVolume(v / 100.0))
        self.player.positionChanged.connect(self.update_music_position)
        self.player.mediaStatusChanged.connect(self.on_media_status)

        return page

    # --------------------------- page 2 ---------------------------
    def build_security_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # JSFuck
        js_box = QGroupBox("JSFUCK")
        jl = QGridLayout(js_box)
        jl.setContentsMargins(4, 4, 4, 4)
        self.js_input = QTextEdit()
        self.js_input.setPlaceholderText("JavaScript text → JSFuck")
        self.js_input.setMinimumHeight(160)
        self.js_output = QTextEdit()
        self.js_output.setReadOnly(True)
        self.js_output.setMinimumHeight(220)
        js_btn = QPushButton("ENCODE")
        js_btn.clicked.connect(self.encode_jsfuck)
        jl.addWidget(QLabel("INPUT"), 0, 0)
        jl.addWidget(self.js_input, 0, 1)
        jl.addWidget(js_btn, 0, 2)
        jl.addWidget(QLabel("OUTPUT"), 1, 0)
        jl.addWidget(self.js_output, 1, 1, 1, 2)

        # URL / common encoders
        codec_box = QGroupBox("ENCODE / DECODE")
        cl = QGridLayout(codec_box)
        cl.setContentsMargins(4, 4, 4, 4)
        self.codec_mode = QComboBox()
        self.codec_mode.addItems([
            "URL encode", "URL decode", "URL encode (+)", "URL decode (+)",
            "Double URL encode", "Double URL decode", "Base64 encode", "Base64 decode",
            "Base64URL encode", "Base64URL decode", "Hex encode", "Hex decode",
            "Unicode escape encode", "Unicode escape decode", "HTML entity encode",
            "HTML entity decode", "JWT payload decode",
        ])
        self.codec_input = QTextEdit()
        self.codec_input.setMaximumHeight(80)
        self.codec_output = QTextEdit()
        self.codec_output.setReadOnly(True)
        self.codec_output.setMaximumHeight(90)
        cbtn = QPushButton("RUN")
        cbtn.clicked.connect(self.run_codec)
        cl.addWidget(self.codec_mode, 0, 0)
        cl.addWidget(cbtn, 0, 1)
        cl.addWidget(QLabel("INPUT"), 1, 0)
        cl.addWidget(self.codec_input, 1, 1)
        cl.addWidget(QLabel("OUTPUT"), 2, 0)
        cl.addWidget(self.codec_output, 2, 1)
        layout.addWidget(codec_box)

        # NS / dig
        net_grid = QGridLayout()
        net_grid.setContentsMargins(0, 0, 0, 0)
        ns_box, self.ns_cmd, self.ns_target, self.ns_output = self.make_command_box("NSLOOKUP", "nslookup")
        dig_box, self.dig_cmd, self.dig_target, self.dig_output = self.make_command_box("DIG", "dig")
        net_grid.addWidget(ns_box, 0, 0)
        net_grid.addWidget(dig_box, 0, 1)
        layout.addLayout(net_grid)

        # Nmap
        nmap_box = QGroupBox("NMAP FAST SCAN")
        nl = QVBoxLayout(nmap_box)
        nl.setContentsMargins(4, 4, 4, 4)
        nrow = QHBoxLayout()
        self.nmap_target = QLineEdit()
        self.nmap_target.setPlaceholderText("Target IP / hostname / authorized host")
        self.nmap_target.setText("127.0.0.1")
        scan_btn = QPushButton("FAST SCAN")
        scan_btn.clicked.connect(self.run_nmap)
        self.nmap_status = QLabel("nmap -T4 -F -n --open")
        nrow.addWidget(self.nmap_target, 1)
        nrow.addWidget(scan_btn)
        nrow.addWidget(self.nmap_status)
        nl.addLayout(nrow)
        self.nmap_output = QTextEdit()
        self.nmap_output.setReadOnly(True)
        self.nmap_output.setMinimumHeight(300)
        nl.addWidget(self.nmap_output)

        nmap_js_row = QHBoxLayout()
        nmap_js_row.setSpacing(6)
        nmap_js_row.addWidget(nmap_box, 1)
        nmap_js_row.addWidget(js_box, 1)
        layout.addLayout(nmap_js_row)

        # Text intelligence
        ex_box = QGroupBox("SECURITY TEXT EXTRACTOR")
        el = QHBoxLayout(ex_box)
        el.setContentsMargins(4, 4, 4, 4)
        self.extract_input = QTextEdit()
        self.extract_input.setPlaceholderText("Paste large text / source / logs / HTML / JS …")
        self.extract_input.setMinimumHeight(190)
        self.extract_output = QTextEdit()
        self.extract_output.setReadOnly(True)
        self.extract_output.setMinimumHeight(190)
        ex_btn = QPushButton("EXTRACT")
        ex_btn.clicked.connect(self.extract_security_data)
        el.addWidget(self.extract_input, 1)
        el.addWidget(ex_btn)
        el.addWidget(self.extract_output, 1)
        layout.addWidget(ex_box)
        layout.addStretch(1)

        scroll.setWidget(page)
        return scroll

    # --------------------------- page 3: payload lab ---------------------------
    def build_payload_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        header = QGroupBox("PAYLOAD LAB")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(6, 6, 6, 6)
        self.payload_category = QComboBox()
        self.payload_category.addItem("ALL")
        self.payload_search = QLineEdit()
        self.payload_search.setPlaceholderText("Search name / payload / note …")
        reload_btn = QPushButton("↻ RELOAD")
        reload_btn.clicked.connect(self.load_payloads)
        self.payload_count = QLabel("0 payloads")
        hl.addWidget(QLabel("CATEGORY"))
        hl.addWidget(self.payload_category, 1)
        hl.addWidget(self.payload_search, 2)
        hl.addWidget(reload_btn)
        hl.addWidget(self.payload_count)
        layout.addWidget(header)

        self.payload_table = QTableWidget(0, 4)
        self.payload_table.setHorizontalHeaderLabels(["NAME", "RISK", "SOURCE", "CATEGORY"])
        self.payload_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.payload_table.setSelectionMode(QTableWidget.SingleSelection)
        self.payload_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.payload_table.verticalHeader().setVisible(False)
        self.payload_table.horizontalHeader().setStretchLastSection(True)
        self.payload_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.payload_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.payload_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.payload_table.itemSelectionChanged.connect(self.show_payload_details)
        layout.addWidget(self.payload_table, 1)

        detail = QGroupBox("PAYLOAD DETAILS")
        dl = QGridLayout(detail)
        dl.setContentsMargins(6, 6, 6, 6)
        self.payload_name = QLabel("-")
        self.payload_name.setWordWrap(True)
        self.payload_risk = QLabel("-")
        self.payload_source = QLabel("-")
        self.payload_source.setOpenExternalLinks(False)
        self.payload_source.linkActivated.connect(lambda url: QDesktopServices.openUrl(QUrl(url)))
        self.payload_note = QLabel("-")
        self.payload_note.setWordWrap(True)
        self.payload_description = QLabel("-")
        self.payload_description.setWordWrap(True)
        self.payload_value = QTextEdit()
        self.payload_value.setReadOnly(True)
        self.payload_value.setMaximumHeight(115)
        copy_btn = QPushButton("COPY PAYLOAD")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.payload_value.toPlainText()))

        dl.addWidget(QLabel("NAME"), 0, 0)
        dl.addWidget(self.payload_name, 0, 1, 1, 3)
        dl.addWidget(QLabel("RISK"), 1, 0)
        dl.addWidget(self.payload_risk, 1, 1)
        dl.addWidget(QLabel("SOURCE"), 1, 2)
        dl.addWidget(self.payload_source, 1, 3)
        dl.addWidget(QLabel("NOTE"), 2, 0)
        dl.addWidget(self.payload_note, 2, 1, 1, 3)
        dl.addWidget(QLabel("WHAT IT DOES"), 3, 0)
        dl.addWidget(self.payload_description, 3, 1, 1, 3)
        dl.addWidget(QLabel("PAYLOAD"), 4, 0)
        dl.addWidget(self.payload_value, 4, 1, 1, 2)
        dl.addWidget(copy_btn, 4, 3)
        layout.addWidget(detail)

        self.payload_search.textChanged.connect(self.filter_payloads)
        self.payload_category.currentTextChanged.connect(self.filter_payloads)
        self.payload_data = []
        self.load_payloads()
        scroll.setWidget(page)
        return scroll

    def load_payloads(self):
        try:
            with open(PAYLOADS_JSON, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self.payload_data = raw.get("payloads", []) if isinstance(raw, dict) else []
        except Exception as exc:
            self.payload_data = []
            self.payload_count.setText(f"Load error: {exc}")
            return

        categories = sorted({str(x.get("category", "Other")) for x in self.payload_data})
        current = self.payload_category.currentText() if self.payload_category.count() else "ALL"
        self.payload_category.blockSignals(True)
        self.payload_category.clear()
        self.payload_category.addItem("ALL")
        self.payload_category.addItems(categories)
        if current in categories or current == "ALL":
            self.payload_category.setCurrentText(current)
        self.payload_category.blockSignals(False)
        self.filter_payloads()
        self.payload_count.setText(f"{len(self.payload_data)} payloads")

    def filter_payloads(self):
        if not hasattr(self, "payload_table"):
            return
        category = self.payload_category.currentText()
        query = self.payload_search.text().strip().casefold()
        self.payload_table.setRowCount(0)
        for payload in self.payload_data:
            haystack = " ".join(str(payload.get(k, "")) for k in ("name", "payload", "note", "description", "category")).casefold()
            if category != "ALL" and payload.get("category") != category:
                continue
            if query and query not in haystack:
                continue
            row = self.payload_table.rowCount()
            self.payload_table.insertRow(row)
            self.payload_table.setItem(row, 0, qitem(payload.get("name", "-")))
            self.payload_table.setItem(row, 1, qitem(str(payload.get("risk_level", "-" )).upper(), Qt.AlignCenter))
            source = str(payload.get("source", payload.get("source_type", "-")))
            source_item = qitem(source, Qt.AlignCenter)
            source_item.setToolTip("Open source/reference from the details panel")
            self.payload_table.setItem(row, 2, source_item)
            self.payload_table.setItem(row, 3, qitem(payload.get("category", "-")))
            self.payload_table.item(row, 0).setData(Qt.UserRole, payload)
        if self.payload_table.rowCount():
            self.payload_table.selectRow(0)
        else:
            self.show_payload_details()

    def show_payload_details(self):
        items = self.payload_table.selectedItems()
        if not items:
            self.payload_name.setText("-")
            self.payload_risk.setText("-")
            self.payload_source.setText("-")
            self.payload_note.setText("-")
            self.payload_description.setText("-")
            self.payload_value.clear()
            return
        payload = self.payload_table.item(items[0].row(), 0).data(Qt.UserRole)
        self.payload_name.setText(str(payload.get("name", "-")))
        self.payload_risk.setText(str(payload.get("risk_level", "-")).upper())
        refs = payload.get("references", []) or []
        if refs:
            label = str(payload.get("source", "SOURCE"))
            self.payload_source.setText(f'<a href="{refs[0]}">{label}</a>')
        else:
            self.payload_source.setText(str(payload.get("source", "-")))
        self.payload_note.setText(str(payload.get("note", "-")))
        self.payload_description.setText(str(payload.get("description", "-")))
        self.payload_value.setPlainText(str(payload.get("payload", "")))

    def make_command_box(self, title: str, key: str):
        box = QGroupBox(title)
        layout = QGridLayout(box)
        layout.setContentsMargins(4, 4, 4, 4)
        cmds = self.load_commands()
        command = cmds.get(key, f"{key} {{target}}")
        cmd_edit = QLineEdit(command)
        target = QLineEdit()
        target.setPlaceholderText("Target / domain / IP")
        output = QTextEdit()
        output.setReadOnly(True)
        output.setMaximumHeight(130)
        run_btn = QPushButton("RUN")
        save_btn = QPushButton("SAVE")

        def save_command():
            data = self.load_commands()
            data[key] = cmd_edit.text().strip()
            self.save_commands(data)

        def run_command_ui():
            template = cmd_edit.text().strip()
            value = target.text().strip()
            if not template:
                output.setPlainText("Command is empty.")
                return
            try:
                command_line = template.format(target=value)
            except Exception as exc:
                output.setPlainText(f"Template error: {exc}")
                return
            self.start_command(command_line, output)

        run_btn.clicked.connect(run_command_ui)
        save_btn.clicked.connect(save_command)
        layout.addWidget(QLabel("CMD"), 0, 0)
        layout.addWidget(cmd_edit, 0, 1, 1, 2)
        layout.addWidget(save_btn, 0, 3)
        layout.addWidget(QLabel("TARGET"), 1, 0)
        layout.addWidget(target, 1, 1, 1, 2)
        layout.addWidget(run_btn, 1, 3)
        layout.addWidget(output, 2, 0, 1, 4)
        return box, cmd_edit, target, output

    # --------------------------- clock ---------------------------
    def update_clocks(self):
        self.update_selected_clock()

    def update_selected_clock(self):
        idx = self.clock_city.currentIndex()
        if idx < 0:
            return
        city, zone = CITIES[idx]
        dt = now_in_zone(zone)
        self.clock_time.setText(dt.strftime("%H:%M:%S"))
        self.clock_date.setText(dt.strftime("%Y-%m-%d %a"))
        self.clock_zone.setText(zone)

    # --------------------------- proxy ---------------------------
    def refresh_proxy(self):
        settings = ProxyManager.get_proxy()
        self.proxy_enabled.setChecked(settings["enabled"])
        server = settings["server"]
        self.proxy_server.setText(server if server else f"{local_ipv4()}:8080")

    def apply_proxy(self):
        server = self.proxy_server.text().strip()
        if self.proxy_enabled.isChecked() and not server:
            QMessageBox.warning(self, "Proxy", "Enter proxy server first.")
            return
        try:
            ProxyManager.set_proxy(self.proxy_enabled.isChecked(), server or None)
            self.refresh_proxy()
        except Exception as exc:
            QMessageBox.critical(self, "Proxy", str(exc))

    def disable_proxy(self):
        try:
            ProxyManager.set_proxy(False)
            self.refresh_proxy()
        except Exception as exc:
            QMessageBox.critical(self, "Proxy", str(exc))

    # --------------------------- ports ---------------------------
    def refresh_ports(self):
        if self.port_thread is not None and self.port_thread.isRunning():
            return
        self.port_status.setText("Loading…")
        self.port_table.setRowCount(0)
        self.port_thread = QThread(self)
        self.port_worker = PortScannerWorker()
        self.port_worker.moveToThread(self.port_thread)
        self.port_thread.started.connect(self.port_worker.run)
        self.port_worker.finished.connect(self.on_ports_loaded)
        self.port_worker.failed.connect(self.on_ports_failed)
        self.port_worker.finished.connect(self.port_thread.quit)
        self.port_worker.failed.connect(self.port_thread.quit)
        self.port_worker.finished.connect(self.port_worker.deleteLater)
        self.port_worker.failed.connect(self.port_worker.deleteLater)
        self.port_thread.finished.connect(self.port_thread.deleteLater)
        self.port_thread.finished.connect(self._clear_port_thread)
        self.port_thread.start()

    def _clear_port_thread(self):
        self.port_thread = None
        self.port_worker = None

    def on_ports_loaded(self, rows):
        self.port_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                self.port_table.setItem(r, c, qitem(value))
        self.port_status.setText(f"{len(rows)} endpoints")

    def on_ports_failed(self, msg):
        self.port_status.setText("Error")
        self.port_table.setRowCount(0)
        # Keep the compact page usable; show the error in status instead of a modal popup.
        self.port_status.setToolTip(msg)

    # --------------------------- music ---------------------------
    def load_music_library(self):
        try:
            data = json.loads(MUSIC_JSON.read_text(encoding="utf-8"))
            tracks = data.get("tracks", []) if isinstance(data, dict) else []
            if tracks and isinstance(tracks[0], dict):
                paths = [x.get("path", "") for x in tracks if x.get("path")]
            else:
                paths = [str(x) for x in tracks if x]
            paths = list(dict.fromkeys([p for p in paths if Path(p).exists()]))
        except Exception:
            paths = []
        self.current_tracks = paths
        self.music_list.clear()
        for path in paths:
            item = QListWidgetItem(Path(path).name)
            item.setToolTip(path)
            item.setData(Qt.UserRole, path)
            self.music_list.addItem(item)
        self.music_status.setText(f"{len(paths)} tracks")

    def save_music_library(self):
        MUSIC_JSON.write_text(json.dumps({"tracks": [{"path": p, "name": Path(p).name} for p in self.current_tracks]}, ensure_ascii=False, indent=2), encoding="utf-8")

    def choose_music_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select music folder", str(BASE_DIR)
        )
        if folder:
            self.scan_music(Path(folder))

    def scan_music(self, root: Path | str):
        if self.music_thread is not None and self.music_thread.isRunning():
            return
        root = Path(root).resolve()
        if not root.is_dir():
            self.music_status.setText("Invalid folder")
            return

        self.music_scan_btn.setEnabled(False)
        self.music_folder_btn.setEnabled(False)
        self.music_progress.setVisible(True)
        self.music_status.setText(f"Scanning {root} …")
        self._music_scan_seen = {str(p).casefold() for p in self.current_tracks}

        self.music_thread = QThread(self)
        self.music_worker = MusicScanWorker(root)
        self.music_worker.moveToThread(self.music_thread)
        self.music_thread.started.connect(self.music_worker.run)
        self.music_worker.found.connect(self.on_music_found)
        self.music_worker.progress.connect(self.music_status.setText)
        self.music_worker.finished.connect(self.on_music_scan_finished)
        self.music_worker.failed.connect(self.on_music_scan_failed)
        self.music_worker.finished.connect(self.music_thread.quit)
        self.music_worker.failed.connect(self.music_thread.quit)
        self.music_worker.finished.connect(self.music_worker.deleteLater)
        self.music_worker.failed.connect(self.music_worker.deleteLater)
        self.music_thread.finished.connect(self.music_thread.deleteLater)
        self.music_thread.finished.connect(self._clear_music_thread)
        self.music_thread.start()

    def _clear_music_thread(self):
        self.music_thread = None
        self.music_worker = None

    def on_music_found(self, path):
        key = str(path).casefold()
        if key in self._music_scan_seen:
            return
        self._music_scan_seen.add(key)
        self.current_tracks.append(str(path))
        item = QListWidgetItem(Path(path).name)
        item.setToolTip(path)
        item.setData(Qt.UserRole, path)
        self.music_list.addItem(item)

    def on_music_scan_finished(self, paths):
        # Append newly discovered tracks; never replace the existing library.
        merged = []
        seen = set()
        for path in list(self.current_tracks) + list(paths):
            path = str(path)
            key = path.casefold()
            if key not in seen and Path(path).exists():
                seen.add(key)
                merged.append(path)
        self.current_tracks = merged
        self.save_music_library()
        self.music_scan_btn.setEnabled(True)
        self.music_folder_btn.setEnabled(True)
        self.music_progress.setVisible(False)
        self.music_status.setText(f"{len(self.current_tracks)} tracks")

    def on_music_scan_failed(self, msg):
        self.music_scan_btn.setEnabled(True)
        self.music_folder_btn.setEnabled(True)
        self.music_progress.setVisible(False)
        self.music_status.setText(f"Scan error: {msg}")

    def play_selected(self, item=None):
        if item is None:
            item = self.music_list.currentItem()
        if item is None:
            return
        path = item.data(Qt.UserRole)
        self.music_index = self.music_list.row(item)
        self.player.setSource(QUrl.fromLocalFile(path))
        self.player.play()
        self.music_title.setText(Path(path).name)
        self.play_btn.setText("PAUSE")

    def toggle_play(self):
        if self.player.playbackState() == QMediaPlayer.PlayingState:
            self.player.pause()
            self.play_btn.setText("PLAY")
        elif self.player.source().isValid():
            self.player.play()
            self.play_btn.setText("PAUSE")
        else:
            self.play_selected()

    def stop_music(self):
        self.player.stop()
        self.play_btn.setText("PLAY")

    def play_next(self):
        count = self.music_list.count()
        if not count:
            return
        self.music_index = (self.music_index + 1) % count
        self.music_list.setCurrentRow(self.music_index)
        self.play_selected(self.music_list.currentItem())

    def play_previous(self):
        count = self.music_list.count()
        if not count:
            return
        self.music_index = (self.music_index - 1) % count
        self.music_list.setCurrentRow(self.music_index)
        self.play_selected(self.music_list.currentItem())

    def update_music_position(self, position):
        # The player stays intentionally minimal; position is available for later UI additions.
        _ = position

    def on_media_status(self, status):
        if status == QMediaPlayer.EndOfMedia:
            self.play_next()

    # --------------------------- page 2 tools ---------------------------
    def encode_jsfuck(self):
        text = self.js_input.toPlainText()
        if not text:
            self.js_output.setPlainText("")
            return
        result, unsupported = self.jsfuck.encode(text)
        if unsupported:
            shown = " ".join(repr(x) for x in unsupported)
            self.js_output.setPlainText(
                "Unsupported character(s): " + shown + "\n\n"
                "This compact encoder currently covers common JS/XSS characters."
            )
        else:
            self.js_output.setPlainText(result)

    def run_codec(self):
        try:
            self.codec_output.setPlainText(Codec.transform(self.codec_mode.currentText(), self.codec_input.toPlainText()))
        except Exception as exc:
            self.codec_output.setPlainText(f"Error: {exc}")

    def start_command(self, command: str, output_widget: QTextEdit):
        output_widget.setPlainText(f"> {command}\n\nRunning…")
        self.cmd_thread = QThread(self)
        self.cmd_worker = CommandWorker(command, 45)
        self.cmd_worker.moveToThread(self.cmd_thread)
        self.cmd_thread.started.connect(self.cmd_worker.run)

        # IMPORTANT: CommandWorker runs in a worker thread. Never touch a
        # QTextEdit/QTextDocument from that thread. The previous inline Python
        # callback could execute in the worker thread and caused:
        #   QObject: Cannot create children for a parent that is in a different thread.
        # Store the target widget on the GUI object and deliver the result to a
        # real MainWindow slot, which Qt invokes in the GUI thread.
        self.cmd_output_widget = output_widget
        self.cmd_worker.finished.connect(self._command_finished)
        self.cmd_worker.finished.connect(self.cmd_thread.quit)
        self.cmd_worker.finished.connect(self.cmd_worker.deleteLater)
        self.cmd_thread.finished.connect(self.cmd_thread.deleteLater)
        self.cmd_thread.start()

    @Slot(bool, str, str)
    def _command_finished(self, ok, out, err):
        output_widget = getattr(self, "cmd_output_widget", None)
        if output_widget is None:
            return
        text = out or ""
        if err:
            text = (text + "\n\n" if text else "") + err
        if not text:
            text = "(no output)"
        output_widget.setPlainText(text)

    def run_nmap(self):
        target = self.nmap_target.text().strip()
        if not target:
            self.nmap_output.setPlainText("Target is required.")
            return

        # Do not run Nmap through a shell. QProcess gives us an asynchronous
        # process with an explicit timeout, so a slow/blocked scan cannot
        # freeze or terminate the Qt GUI.
        if self.nmap_process is not None and self.nmap_process.state() != QProcess.NotRunning:
            self.nmap_output.setPlainText("A scan is already running.")
            return

        # Basic target sanity check. QProcess is not shell-based, but rejecting
        # shell/control characters also prevents accidental malformed targets.
        if not re.fullmatch(r"[A-Za-z0-9_.:\-\[\]/]+", target):
            self.nmap_output.setPlainText("Invalid target. Enter an IP address, IPv6 address, hostname, or CIDR.")
            return

        self.nmap_output.setPlainText(
            f"> nmap -Pn -T4 -F -n --open --host-timeout 35s --max-retries 1 {target}\n\nScanning…"
        )
        self.nmap_status.setText("SCANNING…")

        self.nmap_process = QProcess(self)
        self.nmap_process.setProgram("nmap")
        self.nmap_process.setArguments([
            "-Pn", "-T4", "-F", "-n", "--open",
            "--host-timeout", "35s",
            "--max-retries", "1",
            target,
        ])
        self.nmap_process.setProcessChannelMode(QProcess.SeparateChannels)

        self.nmap_process.readyReadStandardOutput.connect(self._nmap_read_output)
        self.nmap_process.readyReadStandardError.connect(self._nmap_read_error)
        self.nmap_process.errorOccurred.connect(self._nmap_error)
        self.nmap_process.finished.connect(self._nmap_finished)

        self.nmap_timer = QTimer(self)
        self.nmap_timer.setSingleShot(True)
        self.nmap_timer.timeout.connect(self._nmap_timeout)
        self.nmap_process.start()
        self.nmap_timer.start(45000)

    def _nmap_append(self, text: str):
        if not text:
            return
        current = self.nmap_output.toPlainText()
        if current.endswith("Scanning…"):
            current += "\n"
        self.nmap_output.setPlainText(current + text.rstrip() + "\n")
        cursor = self.nmap_output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.nmap_output.setTextCursor(cursor)

    def _nmap_read_output(self):
        if self.nmap_process is not None:
            data = bytes(self.nmap_process.readAllStandardOutput()).decode("utf-8", errors="replace")
            self._nmap_append(data)

    def _nmap_read_error(self):
        if self.nmap_process is not None:
            data = bytes(self.nmap_process.readAllStandardError()).decode("utf-8", errors="replace")
            self._nmap_append(data)

    def _nmap_error(self, error):
        if self.nmap_process is None:
            return
        if error == QProcess.FailedToStart:
            self.nmap_status.setText("NMAP NOT FOUND")
            self._nmap_append("ERROR: Nmap could not be started. Check that nmap.exe is installed and available in PATH.")
        elif error != QProcess.Crashed:
            self._nmap_append(f"Nmap process error: {self.nmap_process.errorString()}")

    def _nmap_finished(self, exit_code, exit_status):
        if self.nmap_timer is not None:
            self.nmap_timer.stop()
        self._nmap_read_output()
        self._nmap_read_error()
        if exit_status == QProcess.NormalExit:
            self.nmap_status.setText(f"DONE (exit {exit_code})")
        else:
            self.nmap_status.setText("NMAP STOPPED")
        self.nmap_process.deleteLater()
        self.nmap_process = None
        if self.nmap_timer is not None:
            self.nmap_timer.deleteLater()
            self.nmap_timer = None

    def _nmap_timeout(self):
        if self.nmap_process is None or self.nmap_process.state() == QProcess.NotRunning:
            return
        self.nmap_status.setText("TIMEOUT")
        self._nmap_append("\n[!] Scan exceeded 45 seconds. Nmap was terminated; the application remains running.")
        self.nmap_process.kill()

    def extract_security_data(self):
        text = self.extract_input.toPlainText()
        data = Extractor.extract(text)
        chunks = []
        for key, values in data.items():
            chunks.append(f"[{key}] ({len(values)})")
            chunks.append("\n".join(values) if values else "-")
            chunks.append("")
        self.extract_output.setPlainText("\n".join(chunks).strip())

    def closeEvent(self, event):
        try:
            self.player.stop()
        except Exception:
            pass
        try:
            if self.nmap_timer is not None:
                self.nmap_timer.stop()
            if self.nmap_process is not None and self.nmap_process.state() != QProcess.NotRunning:
                self.nmap_process.kill()
        except Exception:
            pass
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(str(BASE_DIR / "assets" / "sasan_logo.svg")))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()