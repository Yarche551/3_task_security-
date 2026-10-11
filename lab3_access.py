"""ЛР3 - защищенный программный модуль с функциями управления доступом к ресурсам системы.

Текстовый редактор с каталогом файлов и двумя моделями управления доступом:
  * дискреционная (DAC) - матрица доступа «пользователь x файл» (Табл. 1): права назначает
    администратор, право назначения прав на файл может быть передоверено пользователю (право A);
  * мандатная (MAC, модель Белла-ЛаПадулы) - уровни допуска субъектов и грифы файлов S1 > S2 > S3
    (Табл. 2), владелец файла задает его доступность для других субъектов и гриф не выше своего
    уровня (Табл. 3); читать можно файлы с грифом не выше своего уровня, писать - с грифом не ниже.
Каждое обращение к файлу проходит через монитор обращений (класс Monitor) и пишется в журнал.
Вход - ID и пароль, как в ЛР2 (scrypt + соль, 3 неудачные попытки - завершение работы).
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import sys
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, simpledialog, ttk

MAX_ATTEMPTS = 3                     # предел неудачных попыток входа
SCRYPT_N = 2 ** 14                   # параметр сложности scrypt (из ЛР2)
SALT_BYTES = 16                      # длина соли
MAX_TEXT = 100_000                   # предельный размер файла, символов

DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
DB_FILE = os.path.join(DIR, "access_lr3.db")

# стартовая учетка администратора (пароль стоит сменить после первого входа)
ADMIN_ID, ADMIN_PASS = "0000", "admin1"

RE_ID = r"[0-9]{4}"
RE_NAME = r"[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9 _-]{0,29}"
RE_FILE = r"[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9_.-]{0,39}"
TITLE = ("", 14, "bold")
BOLD = ("", 12, "bold")

OPS = {"R": "читать", "C": "копировать", "E": "редактировать"}
DAC_RIGHTS = {"R": "чтение", "C": "копирование", "E": "редактирование", "A": "передача прав"}
ACTIONS = {"R": "чтение", "C": "копирование", "E": "редактирование", "A": "атрибуты файла"}
LEVELS = ["S1", "S2", "S3"]
RANK = {"S1": 3, "S2": 2, "S3": 1}            # S1 > S2 > S3
MODELS = {"dac": "дискреционная", "mac": "мандатная"}
ROLES = {"admin": "администратор", "user": "пользователь"}

# ---- исходные данные (информационный фонд, создается при первом запуске)
# Табл. 1 - дискреционная модель: файлы создает администратор и назначает права
DAC_USERS = [("1001", "Пользователь 1", "user01"),
             ("1002", "Пользователь 2", "user02"),
             ("1003", "Пользователь 3", "user03")]
DAC_FILES = {
    "Fa": "Отчет отдела продаж за 3 квартал.\nВыручка: 12,4 млн руб., план выполнен на 104%.\n",
    "Fb": "Протокол совещания от 02.10.2026.\nПовестка: переход на новую CRM-систему.\n"
          "Ответственный: Петров П. А.\n",
    "Fc": "Инструкция по резервному копированию.\n1. Копия БД создается ежедневно в 02:00.\n"
          "2. Копии хранятся 30 дней.\n",
}
DAC_TABLE = {"1001": {"Fa": "CE", "Fb": "E", "Fc": "E"},
             "1002": {"Fa": "RE", "Fb": "RC", "Fc": "CE"},
             "1003": {"Fa": "E", "Fb": "CE", "Fc": "E"}}
# Табл. 2 - мандатная модель: ID, имя, пароль, уровень допуска, функции, разрешенные администратором
MAC_USERS = [("2001", "A", "subja1", "S1", "RE"),
             ("2002", "B", "subjb2", "S2", "R"),
             ("2003", "C", "subjc3", "S3", "RE"),
             ("2004", "D", "subjd4", "S2", "R")]
# Табл. 3 (пример) - файл, владелец (создатель), гриф, доступность для остальных субъектов
MAC_FILES = [("Fa", "2001", "S1", {"2002": 1, "2003": 0, "2004": 0}),
             ("Fb", "2002", "S2", {"2001": 1, "2003": 1, "2004": 1}),
             ("Fc", "2003", "S3", {"2001": 0, "2002": 1, "2004": 1})]
MAC_TEXT = {
    "Fa": "[S1] План развертывания защищенного узла связи на объекте N7.\nСрок: 4 квартал.\n",
    "Fb": "[S2] График смены ключей шифрования на 4 квартал.\nОтветственный: субъект B.\n",
    "Fc": "[S3] Список сотрудников, допущенных в серверную.\n1. Иванов И. С.\n2. Петров П. А.\n",
}


# ---------------------------------------------------------------- пароли (из ЛР2)

def new_salt():
    return secrets.token_hex(SALT_BYTES)


def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=SCRYPT_N, r=8, p=1).hex()


def check_password(password, salt, stored_hash):
    # сравнение за постоянное время
    return hmac.compare_digest(hash_password(password, salt), stored_hash)


def pass_ok(p):
    # 6 символов: латинские буквы и цифры, нужны и те и другие
    return len(p) == 6 and p.isascii() and p.isalnum() and not p.isdigit() and not p.isalpha()


def norm_rights(s, order="RCEA"):
    return "".join(r for r in order if r in s)


def fmt_rights(s, sep=", "):
    s = norm_rights(s)
    return sep.join(s) if s else "—"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- база данных

class DB:
    def __init__(self, path=DB_FILE):
        new = not os.path.exists(path)
        self.con = sqlite3.connect(path)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys = ON")
        # безопасность повторного использования объектов: удаленные данные затираются нулями
        self.con.execute("PRAGMA secure_delete = ON")
        self.con.executescript("""
            CREATE TABLE IF NOT EXISTS users (          -- субъекты и их атрибуты
                id        TEXT PRIMARY KEY,
                name      TEXT NOT NULL UNIQUE,
                role      TEXT NOT NULL CHECK(role IN ('admin','user')),
                model     TEXT CHECK(model IN ('dac','mac')),          -- модель доступа пользователя
                clearance TEXT CHECK(clearance IN ('S1','S2','S3')),   -- уровень допуска (MAC)
                funcs     TEXT NOT NULL DEFAULT '',                    -- функции, разрешенные админом (MAC)
                salt      TEXT NOT NULL,
                pass_hash TEXT NOT NULL,
                changed   TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS files (          -- объекты: файлы каталогов DAC и MAC
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                model   TEXT NOT NULL CHECK(model IN ('dac','mac')),
                name    TEXT NOT NULL,
                owner   TEXT NOT NULL REFERENCES users(id),
                label   TEXT CHECK(label IN ('S1','S2','S3')),         -- гриф (MAC)
                content TEXT NOT NULL DEFAULT '',
                created TEXT NOT NULL,
                changed TEXT NOT NULL,
                UNIQUE(model, name));
            CREATE TABLE IF NOT EXISTS dac_acl (        -- матрица доступа DAC (Табл. 1)
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                rights  TEXT NOT NULL,                                 -- R, C, E, A
                PRIMARY KEY(file_id, user_id));
            CREATE TABLE IF NOT EXISTS mac_perm (       -- доступность файла для субъектов (Табл. 3)
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
                PRIMARY KEY(file_id, user_id));
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS access_log (     -- журнал монитора обращений
                n      INTEGER PRIMARY KEY AUTOINCREMENT,
                time   TEXT NOT NULL,
                uid    TEXT,
                model  TEXT,
                object TEXT,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                reason TEXT);
        """)
        if new:
            self.seed()

    def seed(self):
        self.add_user(ADMIN_ID, "Администратор", ADMIN_PASS, "admin", None)
        for uid, name, pwd in DAC_USERS:
            self.add_user(uid, name, pwd, "user", "dac")
        for uid, name, pwd, level, funcs in MAC_USERS:
            self.add_user(uid, name, pwd, "user", "mac", level, funcs)
        for name, text in DAC_FILES.items():
            fid = self.add_file("dac", name, ADMIN_ID, None, text)
            for uid, row in DAC_TABLE.items():
                self.set_dac(fid, uid, row[name])
        for name, owner, label, perms in MAC_FILES:
            fid = self.add_file("mac", name, owner, label, MAC_TEXT[name])
            for uid, allowed in perms.items():
                self.set_perm(fid, uid, allowed)
        self.set("strict_write", "0")
        self.log(ADMIN_ID, None, None, "создание БД", "выполнено", "исходные данные Табл. 1-3")

    # --- настройки и журнал
    def get(self, key, default=""):
        row = self.con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set(self, key, value):
        with self.con:
            self.con.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (key, str(value)))

    def log(self, uid, model, obj, action, result, reason=""):
        with self.con:
            self.con.execute("INSERT INTO access_log(time, uid, model, object, action, result, reason) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?)", (now(), uid, model, obj, action, result, reason))

    # --- пользователи
    def add_user(self, uid, name, password, role, model, clearance=None, funcs=""):
        salt = new_salt()
        with self.con:
            self.con.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             (uid, name, role, model, clearance, norm_rights(funcs, "RCE"),
                              salt, hash_password(password, salt), now()))

    def user(self, uid):
        return self.con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    def users(self, model=None):
        if model is None:
            return self.con.execute("SELECT * FROM users ORDER BY role, id").fetchall()
        return self.con.execute("SELECT * FROM users WHERE role = 'user' AND model = ? ORDER BY id",
                                (model,)).fetchall()

    def update_user(self, uid, name, clearance, funcs):
        with self.con:
            self.con.execute("UPDATE users SET name = ?, clearance = ?, funcs = ? WHERE id = ?",
                             (name, clearance, norm_rights(funcs, "RCE"), uid))

    def set_password(self, uid, password):
        salt = new_salt()           # новая соль при каждой смене пароля
        with self.con:
            self.con.execute("UPDATE users SET salt = ?, pass_hash = ?, changed = ? WHERE id = ?",
                             (salt, hash_password(password, salt), now(), uid))

    def delete_user(self, uid):
        with self.con:
            self.con.execute("DELETE FROM users WHERE id = ?", (uid,))

    # --- файлы
    def add_file(self, model, name, owner, label, content=""):
        with self.con:
            cur = self.con.execute("INSERT INTO files(model, name, owner, label, content, created, changed) "
                                   "VALUES (?, ?, ?, ?, ?, ?, ?)", (model, name, owner, label, content, now(), now()))
        return cur.lastrowid

    def file(self, fid):
        return self.con.execute("SELECT * FROM files WHERE id = ?", (fid,)).fetchone()

    def files(self, model):
        return self.con.execute("SELECT * FROM files WHERE model = ? ORDER BY name", (model,)).fetchall()

    def owned_files(self, uid):
        return [r[0] for r in self.con.execute("SELECT name FROM files WHERE owner = ? ORDER BY name", (uid,))]

    def set_content(self, fid, content):
        with self.con:
            self.con.execute("UPDATE files SET content = ?, changed = ? WHERE id = ?", (content, now(), fid))

    def set_label(self, fid, label):
        with self.con:
            self.con.execute("UPDATE files SET label = ? WHERE id = ?", (label, fid))

    def delete_file(self, fid):
        with self.con:
            self.con.execute("DELETE FROM files WHERE id = ?", (fid,))

    def copy_attrs(self, src, dst):
        # копия наследует атрибуты безопасности оригинала: матрицу доступа / доступность
        with self.con:
            self.con.execute("INSERT INTO dac_acl SELECT ?, user_id, rights FROM dac_acl WHERE file_id = ?", (dst, src))
            self.con.execute("INSERT INTO mac_perm SELECT ?, user_id, allowed FROM mac_perm WHERE file_id = ?", (dst, src))

    # --- матрица доступа DAC
    def dac_rights(self, fid, uid):
        row = self.con.execute("SELECT rights FROM dac_acl WHERE file_id = ? AND user_id = ?", (fid, uid)).fetchone()
        return row[0] if row else ""

    def set_dac(self, fid, uid, rights):
        rights = norm_rights(rights)
        with self.con:
            if rights:
                self.con.execute("INSERT OR REPLACE INTO dac_acl VALUES (?, ?, ?)", (fid, uid, rights))
            else:
                self.con.execute("DELETE FROM dac_acl WHERE file_id = ? AND user_id = ?", (fid, uid))

    # --- доступность файла MAC (владельцу файл доступен всегда, в таблицу он не пишется)
    def perm(self, fid, uid):
        row = self.con.execute("SELECT allowed FROM mac_perm WHERE file_id = ? AND user_id = ?", (fid, uid)).fetchone()
        return bool(row and row[0])

    def set_perm(self, fid, uid, allowed):
        with self.con:
            self.con.execute("INSERT OR REPLACE INTO mac_perm VALUES (?, ?, ?)", (fid, uid, 1 if allowed else 0))


# ---------------------------------------------------------------- монитор обращений

class AccessDenied(Exception):
    pass


class Monitor:
    """Монитор обращений: проверяет каждое обращение субъекта к файлу и пишет его в журнал.
    Других путей к содержимому файлов в программе нет, все правила доступа собраны здесь."""

    def __init__(self, db):
        self.db = db

    def strict(self):
        # строго по тексту задания: писать только в файл, гриф которого выше уровня допуска
        return self.db.get("strict_write") == "1"

    def decide(self, uid, fid, op):
        """Решение без записи в журнал: (разрешено?, причина). op: R, C, E или A."""
        u, f = self.db.user(uid), self.db.file(fid)
        if u is None or f is None:
            return False, "субъект или объект не найден"
        if u["role"] != "user":
            return False, "администратор управляет атрибутами, но не работает с содержимым файлов"
        if u["model"] != f["model"]:
            return False, "файл относится к другой модели доступа"
        if f["model"] == "dac":
            if op in self.db.dac_rights(fid, uid):
                return True, f"право {op} назначено"
            return False, f"право {op} ({DAC_RIGHTS[op]}) на файл {f['name']} не назначено"
        return self.mac_decide(u, f, op)

    def mac_decide(self, u, f, op):
        if not u["clearance"]:
            return False, "субъекту не назначен уровень допуска"
        owner = f["owner"] == u["id"]
        if not owner and not self.db.perm(f["id"], u["id"]):
            return False, f"владелец не предоставил доступ к файлу {f['name']} (разрешение «нет»)"
        if op == "A":
            return (True, "владелец файла") if owner else (False, "атрибуты файла задает только его владелец")
        if op not in u["funcs"]:
            return False, f"функция {op} ({OPS[op]}) не разрешена администратором"
        s, o = RANK[u["clearance"]], RANK[f["label"]]
        if op in ("R", "C"):
            # чтение (и копирование - это тоже чтение): гриф файла не выше уровня допуска
            if s >= o:
                return True, f"гриф файла {f['label']} не выше уровня допуска {u['clearance']}"
            return False, f"чтение вверх запрещено: гриф файла {f['label']} выше уровня допуска {u['clearance']}"
        # запись: гриф файла не ниже уровня допуска (информация не уходит вниз)
        if o > s or (o == s and not self.strict()):
            return True, f"гриф файла {f['label']} не ниже уровня допуска {u['clearance']}"
        if o == s:
            return False, (f"строгое правило записи: писать можно только в файл с грифом выше "
                           f"уровня допуска {u['clearance']}")
        return False, f"запись вниз запрещена: гриф файла {f['label']} ниже уровня допуска {u['clearance']}"

    def check(self, uid, fid, op, note=""):
        """Обращение субъекта к файлу: решение + запись в журнал. При отказе - AccessDenied."""
        ok, reason = self.decide(uid, fid, op)
        f = self.db.file(fid)
        self.db.log(uid, f["model"] if f else None, f["name"] if f else str(fid), ACTIONS[op],
                    "разрешено" if ok else "отказ", reason + (f"; {note}" if note else ""))
        if not ok:
            raise AccessDenied(reason)
        return f

    def check_paste(self, uid, fid, clip):
        """Вставка фрагмента из буфера модуля: нужно право записи, а в MAC еще и гриф
        приемника не ниже грифа источника (иначе это запись вниз через буфер)."""
        ok, reason = self.decide(uid, fid, "E")
        f = self.db.file(fid)
        if ok and f["model"] == "mac" and RANK[f["label"]] < RANK[clip["label"]]:
            ok, reason = False, (f"запись вниз через буфер: фрагмент из файла с грифом {clip['label']} "
                                 f"нельзя вставить в файл с грифом {f['label']}")
        self.db.log(uid, f["model"], f["name"], "вставка фрагмента", "разрешено" if ok else "отказ",
                    f"{reason}; источник {clip['src']}")
        if not ok:
            raise AccessDenied(reason)

    def effective(self, uid, fid):
        """Итоговые права субъекта на файл - для каталога и матриц."""
        f = self.db.file(fid)
        ops = [op for op in "RCEA" if self.decide(uid, fid, op)[0]]
        if not ops:
            return "только видит в каталоге"
        text = ", ".join(op for op in ops if op != "A" or f["model"] == "dac")
        if "E" in ops and "R" not in ops:
            text += " (запись без чтения)"
        if "A" in ops and f["model"] == "mac":
            text = (text + ", " if text else "") + "владелец"
        return text

    def require_admin(self, uid, action):
        u = self.db.user(uid)
        if not u or u["role"] != "admin":
            self.db.log(uid, None, None, action, "отказ", "нет роли администратора")
            raise AccessDenied("действие доступно только администратору")


# ---------------------------------------------------------------- операции над файлами

class FileService:
    """Операции текстового редактора над файлами каталога. Каждая начинается с обращения к монитору."""

    def __init__(self, db, mon):
        self.db = db
        self.mon = mon

    def check_name(self, model, name):
        if not re.fullmatch(RE_FILE, name):
            raise ValueError("Имя файла - от 1 до 40 символов: буквы, цифры, «_», «-», «.»;\n"
                             "первый символ - буква или цифра.")
        if name.lower() in (f["name"].lower() for f in self.db.files(model)):
            raise ValueError(f"Файл {name} уже есть в каталоге.")

    def read(self, uid, fid):
        return self.mon.check(uid, fid, "R")["content"]

    def write(self, uid, fid, text, append=False):
        if append and not text.strip():
            raise ValueError("Нет текста для записи.")
        if len(text) > MAX_TEXT:
            raise ValueError(f"Размер файла - не больше {MAX_TEXT} символов.")
        f = self.mon.check(uid, fid, "E", note="дописывание в конец" if append else "сохранение")
        if append:
            old = f["content"]
            text = old + ("\n" if old and not old.endswith("\n") else "") + text
            if len(text) > MAX_TEXT:
                raise ValueError(f"Размер файла - не больше {MAX_TEXT} символов.")
        self.db.set_content(fid, text)

    def copy(self, uid, fid, new_name):
        f = self.db.file(fid)
        if f is None:
            raise AccessDenied("файл не найден")
        self.check_name(f["model"], new_name)
        f = self.mon.check(uid, fid, "C", note=f"создание копии {new_name}")
        new_id = self.db.add_file(f["model"], new_name, f["owner"], f["label"], f["content"])
        self.db.copy_attrs(fid, new_id)
        return new_id

    def create(self, uid, name, label, perms):
        """Табл. 3: субъект создает файл, задает его гриф (не выше своего) и доступность для других."""
        u = self.db.user(uid)
        if not u or u["role"] != "user" or u["model"] != "mac" or not u["clearance"]:
            raise AccessDenied("создавать файлы мандатного каталога может только субъект с уровнем допуска")
        self.check_name("mac", name)
        if label not in LEVELS:
            raise ValueError("Гриф файла - S1, S2 или S3.")
        if RANK[label] > RANK[u["clearance"]]:
            self.db.log(uid, "mac", name, "создание файла", "отказ",
                        f"гриф {label} выше уровня допуска {u['clearance']}")
            raise ValueError(f"Гриф файла ({label}) не может быть выше\n"
                             f"собственного уровня допуска ({u['clearance']}).")
        fid = self.db.add_file("mac", name, uid, label, "")
        for s, allowed in perms.items():
            if s != uid:
                self.db.set_perm(fid, s, allowed)
        self.db.log(uid, "mac", name, "создание файла", "выполнено",
                    f"гриф {label}; доступен: {self.perm_text(fid)}")
        return fid

    def set_mac_attrs(self, uid, fid, label, perms):
        """Владелец меняет доступность файла и может повысить гриф (не выше своего уровня)."""
        f = self.mon.check(uid, fid, "A", note="изменение атрибутов файла")
        u = self.db.user(uid)
        if label not in LEVELS:
            raise ValueError("Гриф файла - S1, S2 или S3.")
        if label != f["label"]:
            if RANK[label] < RANK[f["label"]]:
                self.db.log(uid, "mac", f["name"], "атрибуты файла", "отказ",
                            f"понижение грифа {f['label']} -> {label}")
                raise AccessDenied("понижение грифа (рассекречивание) выполняет только администратор")
            if RANK[label] > RANK[u["clearance"]]:
                raise ValueError(f"Гриф файла ({label}) не может быть выше\n"
                                 f"собственного уровня допуска ({u['clearance']}).")
            self.db.set_label(fid, label)
        for s, allowed in perms.items():
            if s != f["owner"]:
                self.db.set_perm(fid, s, allowed)
        self.db.log(uid, "mac", f["name"], "атрибуты файла", "выполнено",
                    f"гриф {label}; доступен: {self.perm_text(fid)}")

    def perm_text(self, fid):
        f = self.db.file(fid)
        names = [u["name"] for u in self.db.users("mac") if u["id"] != f["owner"] and self.db.perm(fid, u["id"])]
        return ", ".join(names) or "никому"

    def delegate(self, uid, fid, target, rights):
        """DAC, передоверенное право A: пользователь назначает права на файл другим пользователям,
        но только те, которыми обладает сам (право A передает только администратор)."""
        f = self.mon.check(uid, fid, "A", note=f"передача прав пользователю {target}")
        t = self.db.user(target)
        if not t or t["role"] != "user" or t["model"] != "dac":
            raise ValueError("Выберите пользователя дискреционной модели.")
        if target == uid:
            raise AccessDenied("изменять собственные права нельзя")
        own, old = self.db.dac_rights(fid, uid), self.db.dac_rights(fid, target)
        changed = {r for r in "RCE" if (r in rights) != (r in old)}
        foreign = norm_rights("".join(changed - set(own)))
        if foreign:
            self.db.log(uid, "dac", f["name"], "передача прав", "отказ",
                        f"пользователю {target}: нет собственного права {fmt_rights(foreign)}")
            raise AccessDenied(f"передавать и отзывать можно только права, которыми обладаете сами "
                               f"(у вас нет: {fmt_rights(foreign)})")
        new = norm_rights(rights, "RCE") + ("A" if "A" in old else "")
        self.db.set_dac(fid, target, new)
        self.db.log(uid, "dac", f["name"], "передача прав", "выполнено",
                    f"пользователю {target}: {fmt_rights(old)} -> {fmt_rights(new)}")


# ---------------------------------------------------------------- интерфейс

class App(tk.Tk):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.mon = Monitor(db)
        self.fs = FileService(db, self.mon)
        self.fails = 0               # неудачные попытки входа подряд
        self.uid = None
        self.cur = None              # открытый в редакторе файл
        self.clip = None             # буфер обмена модуля (системный буфер не используется)
        self.tried = {}              # протокол проверки: (файл, право) -> (выполнено?, причина)
        self.proto = None
        self.title("ЛР3 - управление доступом к ресурсам системы")
        self.minsize(460, 0)
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.show_login()
        self.eval("tk::PlaceWindow . center")

    def clear(self):
        if self.proto is not None and self.proto.winfo_exists():
            self.proto.destroy()
        for w in self.winfo_children():
            w.destroy()
        self.geometry("")
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)
        return frame

    def set_geometry(self, w, h):
        w, h = min(w, self.winfo_screenwidth() - 40), min(h, self.winfo_screenheight() - 80)
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth() - w) // 2}+{(self.winfo_screenheight() - h) // 3}")

    def make_tree(self, parent, cols, height=8):
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True)
        tree = ttk.Treeview(box, columns=list(cols), show="headings", height=height, selectmode="browse")
        for c, (text, width) in cols.items():
            tree.heading(c, text=text)
            tree.column(c, width=width, minwidth=40, stretch=True)
        sy = ttk.Scrollbar(box, command=tree.yview)
        tree.configure(yscrollcommand=sy.set)
        tree.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        tree.tag_configure("deny", foreground="#b00")
        tree.tag_configure("none", foreground="#888")
        return tree

    def quit_app(self):
        if self.confirm_close():
            self.destroy()

    def logout(self):
        if self.confirm_close():
            self.show_login()

    # ------------------------------------------------ вход
    def show_login(self):
        # при смене пользователя буфер модуля и протокол очищаются
        self.uid, self.cur, self.clip, self.tried = None, None, None, {}
        f = self.clear()
        ttk.Label(f, text="Вход в систему", font=TITLE).grid(row=0, column=0, columnspan=2, pady=(0, 12))
        ttk.Label(f, text="ID (4 цифры):").grid(row=1, column=0, sticky="w")
        ttk.Label(f, text="Пароль (6 символов):").grid(row=2, column=0, sticky="w")
        self.e_id = ttk.Entry(f, width=22)
        self.e_pass = ttk.Entry(f, width=22, show="*")
        self.e_id.grid(row=1, column=1, padx=(8, 0), pady=3)
        self.e_pass.grid(row=2, column=1, padx=(8, 0), pady=3)
        self.e_pass.bind("<Return>", lambda e: self.login())
        left = MAX_ATTEMPTS - self.fails
        ttk.Label(f, text=f"Осталось попыток входа: {left} из {MAX_ATTEMPTS}",
                  foreground="#b00" if left < MAX_ATTEMPTS else "#555").grid(row=3, column=0, columnspan=2, pady=(8, 0))
        btns = ttk.Frame(f)
        btns.grid(row=4, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(btns, text="Войти", command=self.login).pack(side="left")
        ttk.Button(btns, text="Выход", command=self.destroy).pack(side="left", padx=6)
        self.e_id.focus()

    def login(self):
        uid, password = self.e_id.get().strip(), self.e_pass.get().strip()
        # недопустимый формат отсекается до проверки пароля и попыткой не считается
        if not re.fullmatch(RE_ID, uid):
            messagebox.showerror("Недопустимое значение", "ID - ровно 4 цифры.", parent=self)
            return
        if not pass_ok(password):
            messagebox.showerror("Недопустимое значение",
                                 "Пароль - 6 символов: латинские буквы и цифры (и те, и другие).", parent=self)
            return
        u = self.db.user(uid)
        if u:
            ok = check_password(password, u["salt"], u["pass_hash"])
        else:
            hash_password(password, new_salt())    # время ответа не выдает, есть ли такой ID
            ok = False
        if not ok:
            self.fails += 1
            self.db.log(uid, None, None, "вход", "отказ", f"неверный ID или пароль, попытка {self.fails}")
            if self.fails >= MAX_ATTEMPTS:
                self.db.log(uid, None, None, "вход", "отказ", "превышено число попыток - завершение работы")
                messagebox.showerror("Завершение работы", f"Превышено число попыток входа ({MAX_ATTEMPTS}).\n"
                                                          "Работа программы завершается.", parent=self)
                self.destroy()
                return
            messagebox.showerror("Ошибка входа", f"Неверный ID или пароль.\n"
                                                 f"Осталось попыток: {MAX_ATTEMPTS - self.fails}", parent=self)
            self.show_login()
            self.e_id.insert(0, uid)
            self.e_pass.focus()
            return
        self.fails = 0
        if u["role"] == "user" and u["model"] == "mac" and not u["clearance"]:
            self.db.log(uid, "mac", None, "вход", "отказ", "не назначен уровень допуска")
            messagebox.showerror("Ошибка доступа", "Субъекту не назначен уровень допуска -\n"
                                                   "работа в мандатной модели невозможна.\n"
                                                   "Обратитесь к администратору.", parent=self)
            self.show_login()
            return
        self.uid = uid
        self.db.log(uid, u["model"], None, "вход", "разрешено", "успешная аутентификация")
        if u["role"] == "admin":
            self.show_admin()
        else:
            self.show_user()

    def change_own_password(self):
        dlg = PasswordDialog(self, f"Смена пароля (ID {self.uid})", ask_old=True)
        if not dlg.result:
            return
        u = self.db.user(self.uid)
        if not check_password(dlg.result[0], u["salt"], u["pass_hash"]):
            messagebox.showerror("Ошибка", "Текущий пароль введен неверно.", parent=self)
            return
        self.db.set_password(self.uid, dlg.result[1])
        self.db.log(self.uid, u["model"], None, "смена пароля", "выполнено", "новая соль и хэш")
        messagebox.showinfo("Пароль", "Пароль изменен.", parent=self)

    # ------------------------------------------------ рабочее место пользователя (текстовый редактор)
    def show_user(self):
        u = self.db.user(self.uid)
        self.model = u["model"]
        f = self.clear()
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text=f"{MODELS[self.model].capitalize()} модель — {u['name']} (ID {u['id']})",
                  font=TITLE).pack(side="left")
        ttk.Button(top, text="Выход", command=self.quit_app).pack(side="right")
        ttk.Button(top, text="Сменить пользователя", command=self.logout).pack(side="right", padx=6)
        ttk.Button(top, text="Сменить пароль", command=self.change_own_password).pack(side="right")
        if self.model == "mac":
            info = (f"Уровень допуска: {u['clearance']}    функции: {fmt_rights(u['funcs'], '/')}    "
                    f"читать можно файлы с грифом не выше {u['clearance']}, писать - в файлы с грифом "
                    + ("выше " if self.mon.strict() else "не ниже ") + u["clearance"])
        else:
            info = ("Права на файлы назначает администратор (матрица доступа). "
                    "R - читать, C - копировать, E - редактировать, A - передача прав на файл.")
        ttk.Label(f, text=info, foreground="#555").pack(anchor="w", pady=(4, 0))
        self.status = ttk.Label(f, text="", foreground="#555")
        self.status.pack(side="bottom", anchor="w", pady=(8, 0))

        body = ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True, pady=(10, 0))
        left, right = ttk.Frame(body), ttk.Frame(body, padding=(12, 0, 0, 0))
        body.add(left, weight=1)
        body.add(right, weight=2)

        # каталог
        ttk.Label(left, text="Каталог", font=BOLD).pack(anchor="w")
        cols = {"name": ("Файл", 90), "owner": ("Владелец", 110)}
        if self.model == "mac":
            cols["label"] = ("Гриф", 50)
        cols["access"] = ("Ваш доступ", 190)
        self.cat = self.make_tree(left, cols, height=12)
        self.cat.bind("<Double-1>", lambda e: self.do_read())
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Читать (R)", command=self.do_read).grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Копировать (C)", command=self.do_copy).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(btns, text="Редактировать (E)", command=self.do_edit).grid(row=0, column=2, sticky="ew")
        if self.model == "mac":
            ttk.Button(btns, text="Создать файл", command=self.do_create).grid(row=1, column=0, sticky="ew", pady=(4, 0))
            ttk.Button(btns, text="Атрибуты файла", command=self.do_attrs).grid(row=1, column=1, sticky="ew",
                                                                               padx=4, pady=(4, 0))
        else:
            ttk.Button(btns, text="Передать права (A)", command=self.do_attrs).grid(row=1, column=0, sticky="ew",
                                                                                   pady=(4, 0))
        ttk.Button(btns, text="Протокол проверки", command=self.show_protocol).grid(row=1, column=2, sticky="ew",
                                                                                     pady=(4, 0))
        for c in range(3):
            btns.columnconfigure(c, weight=1)

        # редактор
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)
        self.ed_title = ttk.Label(right, text="Файл не открыт", font=BOLD)
        self.ed_title.grid(row=0, column=0, sticky="w")
        self.ed_hint = ttk.Label(right, text="Выберите файл в каталоге и операцию.", foreground="#555",
                                 wraplength=620, justify="left")
        self.ed_hint.grid(row=1, column=0, sticky="w")
        box = ttk.Frame(right)
        box.grid(row=2, column=0, sticky="nsew", pady=6)
        # exportselection=False - выделение не уходит в системный буфер (PRIMARY в X11)
        self.text = tk.Text(box, wrap="word", undo=True, exportselection=False, width=60, height=18,
                            state="disabled")
        sy = ttk.Scrollbar(box, command=self.text.yview)
        self.text.configure(yscrollcommand=sy.set)
        self.text.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        # копирование и вставка - только через буфер модуля и с проверкой прав
        self.text.bind("<<Copy>>", lambda e: self.on_copy())
        self.text.bind("<<Cut>>", lambda e: self.on_copy(cut=True))
        self.text.bind("<<Paste>>", lambda e: self.on_paste())
        self.text.bind("<<PasteSelection>>", lambda e: "break")
        self.text.bind("<Button-1>", lambda e: self.text.focus_set(), add="+")   # фокус и в режиме чтения
        self.blind_box = ttk.Frame(right)
        self.blind_box.grid(row=3, column=0, sticky="w")
        self.v_append = tk.BooleanVar(value=True)
        ttk.Radiobutton(self.blind_box, text="дописать в конец файла", variable=self.v_append,
                        value=True).pack(side="left")
        ttk.Radiobutton(self.blind_box, text="заменить содержимое файла", variable=self.v_append,
                        value=False).pack(side="left", padx=8)
        self.blind_box.grid_remove()
        eb = ttk.Frame(right)
        eb.grid(row=4, column=0, sticky="w")
        self.b_save = ttk.Button(eb, text="Сохранить", command=self.save, state="disabled")
        self.b_save.pack(side="left")
        ttk.Button(eb, text="Закрыть файл", command=self.close_file).pack(side="left", padx=6)

        self.set_geometry(1180, 640)
        self.refresh_catalog()

    def refresh_catalog(self):
        sel = self.cat.selection()
        self.cat.delete(*self.cat.get_children())
        for f in self.db.files(self.model):
            access = self.mon.effective(self.uid, f["id"])
            owner = self.db.user(f["owner"])["name"]
            vals = [f["name"], owner] + ([f["label"]] if self.model == "mac" else []) + [access]
            self.cat.insert("", "end", iid=str(f["id"]), values=vals,
                            tags=("none",) if access.startswith("только") else ())
        if sel and self.cat.exists(sel[0]):
            self.cat.selection_set(sel[0])
        elif self.cat.get_children():
            self.cat.selection_set(self.cat.get_children()[0])
        if self.proto is not None and self.proto.winfo_exists():
            self.proto.refresh()

    def selected_file(self):
        sel = self.cat.selection()
        if not sel:
            messagebox.showerror("Ошибка", "Выберите файл в каталоге.", parent=self)
            return None
        return int(sel[0])

    def set_status(self, text, error=False):
        self.status.config(text=text, foreground="#b00" if error else "#070")

    def passed(self, fid, op, text):
        self.tried[(fid, op)] = (True, text)
        self.set_status(f"{self.db.file(fid)['name']}: {OPS[op]} - команда выполнена. {text}")
        self.refresh_catalog()

    def denied(self, fid, op, err):
        # недопустимое право: ошибка доступа и возврат в форму ввода
        self.tried[(fid, op)] = (False, str(err))
        name = self.db.file(fid)["name"] if self.db.file(fid) else "?"
        self.set_status(f"{name}: {OPS.get(op, op)} - ошибка доступа: {err}", error=True)
        messagebox.showerror("Ошибка доступа", f"Операция «{OPS.get(op, ACTIONS.get(op, op))}» над файлом "
                                               f"{name} запрещена.\n\nПричина: {err}", parent=self)
        if self.proto is not None and self.proto.winfo_exists():
            self.proto.refresh()
        self.cat.focus_set()

    def do_read(self):
        fid = self.selected_file()
        if fid is None or not self.confirm_close():
            return
        try:
            text = self.fs.read(self.uid, fid)
        except AccessDenied as e:
            self.denied(fid, "R", e)
            return
        self.open_editor(fid, "read", text)
        self.passed(fid, "R", "Файл открыт для чтения.")

    def do_edit(self):
        fid = self.selected_file()
        if fid is None or not self.confirm_close():
            return
        try:
            self.mon.check(self.uid, fid, "E", note="открытие для записи")
        except AccessDenied as e:
            self.denied(fid, "E", e)
            return
        if self.mon.decide(self.uid, fid, "R")[0]:
            self.open_editor(fid, "edit", self.fs.read(self.uid, fid))
            self.passed(fid, "E", "Файл открыт для редактирования.")
        else:
            self.open_editor(fid, "blind", "")
            self.passed(fid, "E", "Права чтения нет - запись без просмотра содержимого.")

    def do_copy(self):
        fid = self.selected_file()
        if fid is None:
            return
        try:
            self.mon.check(self.uid, fid, "C", note="запрос имени копии")
        except AccessDenied as e:
            self.denied(fid, "C", e)
            return
        src = self.db.file(fid)
        name = src["name"] + "_копия"
        while True:
            name = simpledialog.askstring("Копирование", f"Имя копии файла {src['name']}:",
                                          initialvalue=name, parent=self)
            if name is None:
                return
            name = name.strip()
            try:
                new_id = self.fs.copy(self.uid, fid, name)
                break
            except ValueError as e:
                messagebox.showerror("Недопустимое значение", str(e), parent=self)
            except AccessDenied as e:
                self.denied(fid, "C", e)
                return
        self.passed(fid, "C", f"Создана копия {name}.")
        self.cat.selection_set(str(new_id))
        messagebox.showinfo("Копирование", f"Создана копия {name}.\nАтрибуты безопасности (владелец, "
                                           + ("гриф, доступность" if self.model == "mac" else "матрица доступа")
                                           + ") унаследованы от файла " + src["name"] + ".", parent=self)

    def do_attrs(self):
        fid = self.selected_file()
        if fid is None:
            return
        try:
            self.mon.check(self.uid, fid, "A", note="открытие атрибутов")
        except AccessDenied as e:
            self.denied(fid, "A", e)
            return
        if self.model == "mac":
            MacFileDialog(self, fid)
        else:
            DelegateDialog(self, fid)
        self.refresh_catalog()

    def do_create(self):
        dlg = MacFileDialog(self)
        if dlg.result:
            self.refresh_catalog()
            self.cat.selection_set(str(dlg.result))
            self.set_status(f"Создан файл {self.db.file(dlg.result)['name']}.")

    # --- редактор
    def open_editor(self, fid, mode, text):
        f = self.db.file(fid)
        self.cur = dict(id=fid, name=f["name"], mode=mode, label=f["label"])
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", text)
        self.text.edit_reset()
        self.text.edit_modified(False)
        gr = f" (гриф {f['label']})" if f["label"] else ""
        can_copy = self.mon.decide(self.uid, fid, "C")[0]
        clip = "копирование фрагментов разрешено (право C)" if can_copy else "копирование фрагментов запрещено (нет права C)"
        if mode == "read":
            self.text.config(state="disabled")
            self.ed_title.config(text=f"{f['name']}{gr} - чтение")
            self.ed_hint.config(text=f"Только просмотр; {clip}.")
            self.b_save.config(state="disabled")
            self.blind_box.grid_remove()
        elif mode == "edit":
            self.ed_title.config(text=f"{f['name']}{gr} - редактирование")
            self.ed_hint.config(text=f"Изменения сохраняются кнопкой «Сохранить»; {clip}.")
            self.b_save.config(state="normal")
            self.blind_box.grid_remove()
        else:
            self.ed_title.config(text=f"{f['name']}{gr} - запись без права чтения")
            self.ed_hint.config(text="Содержимое файла скрыто: права R нет"
                                     + (" (чтение вверх запрещено)" if self.model == "mac" else "")
                                     + ". Введенный текст будет записан в файл.")
            self.b_save.config(state="normal")
            self.v_append.set(True)
            self.blind_box.grid()
        self.text.focus_set()

    def close_file(self):
        if not self.confirm_close():
            return
        self.wipe_editor()

    def wipe_editor(self):
        # безопасность повторного использования: содержимое файла не остается в буфере редактора
        self.cur = None
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.edit_reset()
        self.text.config(state="disabled")
        self.ed_title.config(text="Файл не открыт")
        self.ed_hint.config(text="Выберите файл в каталоге и операцию.")
        self.b_save.config(state="disabled")
        self.blind_box.grid_remove()

    def confirm_close(self):
        if not self.cur or self.cur["mode"] == "read" or not self.text.edit_modified():
            return True
        ans = messagebox.askyesnocancel("Несохраненные изменения",
                                        f"Сохранить изменения в файле {self.cur['name']}?", parent=self)
        if ans is None:
            return False
        return self.save() if ans else True

    def save(self):
        if not self.cur or self.cur["mode"] == "read":
            return False
        fid, text = self.cur["id"], self.text.get("1.0", "end-1c")
        append = self.cur["mode"] == "blind" and self.v_append.get()
        try:
            self.fs.write(self.uid, fid, text, append)
        except AccessDenied as e:
            self.denied(fid, "E", e)
            return False
        except ValueError as e:
            messagebox.showerror("Недопустимое значение", str(e), parent=self)
            return False
        if self.cur["mode"] == "blind":
            self.text.delete("1.0", "end")
        self.text.edit_modified(False)
        self.passed(fid, "E", "Изменения записаны в файл" + (" (дописаны в конец)." if append else "."))
        return True

    def on_copy(self, cut=False):
        if not self.cur or (cut and self.cur["mode"] == "read"):
            return "break"
        try:
            fragment = self.text.get("sel.first", "sel.last")
        except tk.TclError:
            return "break"                     # ничего не выделено
        try:
            self.mon.check(self.uid, self.cur["id"], "C", note="фрагмент в буфер модуля")
        except AccessDenied as e:
            self.denied(self.cur["id"], "C", e)
            return "break"
        self.clip = dict(text=fragment, label=self.cur["label"], src=self.cur["name"])
        if cut:
            self.text.delete("sel.first", "sel.last")
        self.set_status(f"Фрагмент ({len(fragment)} симв.) из {self.cur['name']} - в буфере модуля "
                        f"(системный буфер обмена не используется).")
        return "break"

    def on_paste(self):
        if not self.cur or self.cur["mode"] == "read":
            return "break"
        if not self.clip:
            self.set_status("Буфер модуля пуст (вставка из системного буфера обмена отключена).", error=True)
            return "break"
        try:
            self.mon.check_paste(self.uid, self.cur["id"], self.clip)
        except AccessDenied as e:
            self.set_status(f"Вставка запрещена: {e}", error=True)
            messagebox.showerror("Ошибка доступа", f"Вставка фрагмента запрещена.\n\nПричина: {e}", parent=self)
            return "break"
        try:
            self.text.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        self.text.insert("insert", self.clip["text"])
        return "break"

    # --- протокол проверки (рис. 1, 2: все права проверены? все файлы проверены?)
    def show_protocol(self):
        if self.proto is not None and self.proto.winfo_exists():
            self.proto.lift()
            self.proto.refresh()
        else:
            self.proto = ProtocolWindow(self)

    # ------------------------------------------------ панель администратора
    def show_admin(self):
        f = self.clear()
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="Панель администратора", font=TITLE).pack(side="left")
        ttk.Button(top, text="Выход", command=self.quit_app).pack(side="right")
        ttk.Button(top, text="Сменить пользователя", command=self.show_login).pack(side="right", padx=6)
        ttk.Button(top, text="Сменить свой пароль", command=self.change_own_password).pack(side="right")
        nb = ttk.Notebook(f)
        nb.pack(fill="both", expand=True, pady=(10, 0))
        self.tab_users = ttk.Frame(nb, padding=10)
        self.tab_dac = ttk.Frame(nb, padding=10)
        self.tab_mac = ttk.Frame(nb, padding=10)
        self.tab_log = ttk.Frame(nb, padding=10)
        nb.add(self.tab_dac, text="Дискреционная модель (рис. 1)")
        nb.add(self.tab_mac, text="Мандатная модель (рис. 2)")
        nb.add(self.tab_users, text="Пользователи и атрибуты")
        nb.add(self.tab_log, text="Журнал обращений")
        self.build_dac_tab()
        self.build_mac_tab()
        self.build_users_tab()
        self.build_log_tab()
        self.set_geometry(1220, 700)
        nb.bind("<<NotebookTabChanged>>", lambda e: self.refresh_admin())
        self.refresh_admin()

    def refresh_admin(self):
        self.refresh_users()
        self.refresh_dac()
        self.refresh_mac()
        self.refresh_log()

    def admin_action(self, action):
        try:
            self.mon.require_admin(self.uid, action)
            return True
        except AccessDenied as e:
            messagebox.showerror("Ошибка доступа", str(e), parent=self)
            return False

    @staticmethod
    def list_index(lb):
        sel = lb.curselection()
        return sel[0] if sel else None

    @staticmethod
    def fill_list(lb, items, keep):
        lb.delete(0, "end")
        for it in items:
            lb.insert("end", it)
        if items:
            i = min(keep if keep is not None else 0, len(items) - 1)
            lb.selection_set(i)
            lb.see(i)

    def rebuild_tree(self, box, cols, rows, height):
        for w in box.winfo_children():
            w.destroy()
        tree = self.make_tree(box, cols, height=height)
        for vals in rows:
            tree.insert("", "end", values=vals)
        return tree

    # --- вкладка «Дискреционная модель»: алгоритм администратора рис. 1
    def build_dac_tab(self):
        t = self.tab_dac
        ttk.Label(t, text="Алгоритм (рис. 1): выбор пользователя → выбор файла → назначение прав пользователю "
                          "для выбранного файла → все права назначены? → все файлы рассмотрены? → "
                          "список пользователей исчерпан?", wraplength=1080, justify="left").pack(anchor="w")
        row = ttk.Frame(t)
        row.pack(fill="x", pady=(8, 0))
        b1 = ttk.LabelFrame(row, text="Пользователь", padding=6)
        b1.pack(side="left", fill="y")
        self.dac_ul = tk.Listbox(b1, height=7, width=26, exportselection=False)
        self.dac_ul.pack()
        b2 = ttk.LabelFrame(row, text="Файл", padding=6)
        b2.pack(side="left", fill="y", padx=8)
        self.dac_fl = tk.Listbox(b2, height=7, width=18, exportselection=False)
        self.dac_fl.pack(side="left", fill="y")
        fb = ttk.Frame(b2)
        fb.pack(side="left", fill="y", padx=(6, 0))
        ttk.Button(fb, text="Создать файл", command=self.dac_new_file).pack(fill="x")
        ttk.Button(fb, text="Удалить файл", command=lambda: self.admin_delete_file("dac")).pack(fill="x", pady=(4, 0))
        b3 = ttk.LabelFrame(row, text="Права пользователя на выбранный файл", padding=6)
        b3.pack(side="left", fill="both", expand=True)
        self.dac_vars = {}
        for r, name in DAC_RIGHTS.items():
            v = tk.BooleanVar()
            text = f"{r} - {name}" + (" (может назначать права на файл другим)" if r == "A" else "")
            ttk.Checkbutton(b3, text=text, variable=v).pack(anchor="w")
            self.dac_vars[r] = v
        bb = ttk.Frame(b3)
        bb.pack(anchor="w", pady=(8, 0))
        ttk.Button(bb, text="Назначить", command=lambda: self.dac_assign(False)).pack(side="left")
        ttk.Button(bb, text="Назначить и далее →", command=lambda: self.dac_assign(True)).pack(side="left", padx=6)
        self.dac_progress = ttk.Label(b3, text="", foreground="#555")
        self.dac_progress.pack(anchor="w", pady=(6, 0))
        self.dac_ul.bind("<<ListboxSelect>>", lambda e: self.dac_load())
        self.dac_fl.bind("<<ListboxSelect>>", lambda e: self.dac_load())
        ttk.Label(t, text="Матрица доступа (Табл. 1)   C - копировать, E - редактировать, R - читать, A - передача прав",
                  font=BOLD).pack(anchor="w", pady=(12, 4))
        self.dac_matrix = ttk.Frame(t)
        self.dac_matrix.pack(fill="both", expand=True)

    def refresh_dac(self):
        users, files = self.db.users("dac"), self.db.files("dac")
        self.dac_uids, self.dac_fids = [u["id"] for u in users], [f["id"] for f in files]
        self.fill_list(self.dac_ul, [f"{u['name']} (ID {u['id']})" for u in users], self.list_index(self.dac_ul))
        self.fill_list(self.dac_fl, [f["name"] for f in files], self.list_index(self.dac_fl))
        cols = {"user": ("Файлы / пользователи", 200)}
        cols.update({f"f{f['id']}": (f["name"], 110) for f in files})
        rows = [[u["name"]] + [fmt_rights(self.db.dac_rights(f["id"], u["id"])) for f in files] for u in users]
        self.rebuild_tree(self.dac_matrix, cols, rows, height=6)
        self.dac_load()

    def dac_pair(self):
        ui, fi = self.list_index(self.dac_ul), self.list_index(self.dac_fl)
        return (None, None) if ui is None or fi is None else (ui, fi)

    def dac_load(self):
        ui, fi = self.dac_pair()
        if ui is None:
            for v in self.dac_vars.values():
                v.set(False)
            self.dac_progress.config(text="Выберите пользователя и файл.")
            return
        rights = self.db.dac_rights(self.dac_fids[fi], self.dac_uids[ui])
        for r, v in self.dac_vars.items():
            v.set(r in rights)
        self.dac_progress.config(text=f"Пользователь {ui + 1} из {len(self.dac_uids)}, "
                                      f"файл {fi + 1} из {len(self.dac_fids)}")

    def dac_assign(self, advance):
        ui, fi = self.dac_pair()
        if ui is None:
            messagebox.showerror("Ошибка", "Выберите пользователя и файл.", parent=self)
            return
        if not self.admin_action("назначение прав"):
            return
        uid, fid = self.dac_uids[ui], self.dac_fids[fi]
        rights = "".join(r for r, v in self.dac_vars.items() if v.get())
        old = self.db.dac_rights(fid, uid)
        self.db.set_dac(fid, uid, rights)
        self.db.log(self.uid, "dac", self.db.file(fid)["name"], "назначение прав", "выполнено",
                    f"пользователю {uid}: {fmt_rights(old)} -> {fmt_rights(rights)}")
        if advance:
            fi += 1                                  # все файлы рассмотрены? -> следующий пользователь
            if fi == len(self.dac_fids):
                fi, ui = 0, ui + 1
            if ui == len(self.dac_uids):             # список пользователей исчерпан
                self.refresh_dac()
                messagebox.showinfo("Назначение прав", "Все права назначены, все файлы рассмотрены,\n"
                                                       "список пользователей исчерпан.", parent=self)
                return
            for lb, i in ((self.dac_ul, ui), (self.dac_fl, fi)):
                lb.selection_clear(0, "end")
                lb.selection_set(i)
        self.refresh_dac()

    def dac_new_file(self):
        if not self.admin_action("создание файла"):
            return
        name = ""
        while True:
            name = simpledialog.askstring("Новый файл", "Имя файла дискреционного каталога:", initialvalue=name,
                                          parent=self)
            if name is None:
                return
            name = name.strip()
            try:
                self.fs.check_name("dac", name)
                break
            except ValueError as e:
                messagebox.showerror("Недопустимое значение", str(e), parent=self)
        fid = self.db.add_file("dac", name, self.uid, None, "")
        self.db.log(self.uid, "dac", name, "создание файла", "выполнено", "права пока не назначены")
        self.refresh_dac()
        self.dac_fl.selection_clear(0, "end")
        self.dac_fl.selection_set(self.dac_fids.index(fid))
        self.dac_load()

    def admin_delete_file(self, model):
        lb, ids = (self.dac_fl, self.dac_fids) if model == "dac" else (self.mac_fl, self.mac_fids)
        i = self.list_index(lb)
        if i is None:
            messagebox.showerror("Ошибка", "Выберите файл.", parent=self)
            return
        f = self.db.file(ids[i])
        if not messagebox.askyesno("Удаление", f"Удалить файл {f['name']} ({MODELS[model]} модель)?\n"
                                               "Содержимое будет затерто.", parent=self):
            return
        if not self.admin_action("удаление файла"):
            return
        self.db.delete_file(f["id"])
        self.db.log(self.uid, model, f["name"], "удаление файла", "выполнено", "")
        self.refresh_admin()

    # --- вкладка «Мандатная модель»: алгоритм администратора рис. 2
    def build_mac_tab(self):
        t = self.tab_mac
        ttk.Label(t, text="Алгоритм (рис. 2): выбор пользователя → выбор файла → назначение прав пользователю для "
                          "выбранного файла → назначение грифа пользователю и выбранному файлу → все права назначены? "
                          "→ все файлы рассмотрены? → список пользователей исчерпан?   Уровни: S1 > S2 > S3.",
                  wraplength=1080, justify="left").pack(anchor="w")
        row = ttk.Frame(t)
        row.pack(fill="x", pady=(8, 0))
        b1 = ttk.LabelFrame(row, text="Субъект", padding=6)
        b1.pack(side="left", fill="y")
        self.mac_ul = tk.Listbox(b1, height=7, width=24, exportselection=False)
        self.mac_ul.pack()
        b2 = ttk.LabelFrame(row, text="Файл", padding=6)
        b2.pack(side="left", fill="y", padx=8)
        self.mac_fl = tk.Listbox(b2, height=7, width=24, exportselection=False)
        self.mac_fl.pack()
        ttk.Button(b2, text="Удалить файл", command=lambda: self.admin_delete_file("mac")).pack(fill="x", pady=(4, 0))
        b3 = ttk.LabelFrame(row, text="Назначение", padding=6)
        b3.pack(side="left", fill="both", expand=True)
        self.mac_clear, self.mac_label = tk.StringVar(), tk.StringVar()
        self.mac_allowed = tk.BooleanVar()
        self.mac_funcs = {r: tk.BooleanVar() for r in OPS}
        ttk.Label(b3, text="Уровень допуска субъекта:").grid(row=0, column=0, sticky="w")
        ttk.Combobox(b3, textvariable=self.mac_clear, values=LEVELS, state="readonly", width=6).grid(
            row=0, column=1, sticky="w", padx=6)
        ttk.Label(b3, text="Функции субъекта:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        fr = ttk.Frame(b3)
        fr.grid(row=1, column=1, columnspan=2, sticky="w", padx=6, pady=(4, 0))
        for r, name in OPS.items():
            ttk.Checkbutton(fr, text=f"{r} - {name}", variable=self.mac_funcs[r]).pack(side="left", padx=(0, 8))
        ttk.Label(b3, text="Гриф файла:").grid(row=2, column=0, sticky="w", pady=(4, 0))
        ttk.Combobox(b3, textvariable=self.mac_label, values=LEVELS, state="readonly", width=6).grid(
            row=2, column=1, sticky="w", padx=6, pady=(4, 0))
        self.mac_allowed_cb = ttk.Checkbutton(b3, text="файл доступен субъекту (разрешение «да»)",
                                              variable=self.mac_allowed)
        self.mac_allowed_cb.grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        bb = ttk.Frame(b3)
        bb.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(bb, text="Назначить", command=lambda: self.mac_assign(False)).pack(side="left")
        ttk.Button(bb, text="Назначить и далее →", command=lambda: self.mac_assign(True)).pack(side="left", padx=6)
        self.mac_progress = ttk.Label(b3, text="", foreground="#555")
        self.mac_progress.grid(row=5, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.v_strict = tk.BooleanVar()
        ttk.Checkbutton(b3, text="строгая запись: только в файл с грифом ВЫШЕ допуска (иначе - не ниже)",
                        variable=self.v_strict, command=self.mac_strict).grid(row=6, column=0, columnspan=3,
                                                                              sticky="w", pady=(6, 0))
        b3.columnconfigure(2, weight=1)      # лишняя ширина - в последний столбец, подписи не растягиваются
        self.mac_ul.bind("<<ListboxSelect>>", lambda e: self.mac_load())
        self.mac_fl.bind("<<ListboxSelect>>", lambda e: self.mac_load())

        bottom = ttk.Frame(t)
        bottom.pack(fill="both", expand=True, pady=(12, 0))
        l1 = ttk.Frame(bottom)
        l1.pack(side="left", fill="both")
        ttk.Label(l1, text="Гриф и доступность файлов (Табл. 3)", font=BOLD).pack(anchor="w", pady=(0, 4))
        self.mac_attrs = ttk.Frame(l1)
        self.mac_attrs.pack(fill="both", expand=True)
        l2 = ttk.Frame(bottom)
        l2.pack(side="left", fill="both", expand=True, padx=(12, 0))
        ttk.Label(l2, text="Итоговые права - решение монитора обращений", font=BOLD).pack(anchor="w", pady=(0, 4))
        self.mac_eff = ttk.Frame(l2)
        self.mac_eff.pack(fill="both", expand=True)

    def refresh_mac(self):
        users, files = self.db.users("mac"), self.db.files("mac")
        self.mac_uids, self.mac_fids = [u["id"] for u in users], [f["id"] for f in files]
        names = {u["id"]: u["name"] for u in self.db.users()}
        self.fill_list(self.mac_ul, [f"{u['name']} (ID {u['id']}) - {u['clearance'] or '?'}, "
                                     f"{fmt_rights(u['funcs'], '/')}" for u in users], self.list_index(self.mac_ul))
        self.fill_list(self.mac_fl, [f"{f['name']} - {f['label']}, владелец {names[f['owner']]}" for f in files],
                       self.list_index(self.mac_fl))
        self.v_strict.set(self.mon.strict())
        cols = {"file": ("Файл", 70), "label": ("Гриф", 50), "owner": ("Владелец", 70)}
        cols.update({f"u{u['id']}": (u["name"], 60) for u in users})
        rows = [[f["name"], f["label"], names[f["owner"]]]
                + ["да" if u["id"] == f["owner"] or self.db.perm(f["id"], u["id"]) else "нет" for u in users]
                for f in files]
        self.rebuild_tree(self.mac_attrs, cols, rows, height=6)
        cols = {"subj": ("Субъект", 120)}
        cols.update({f"f{f['id']}": (f"{f['name']} ({f['label']})", 160) for f in files})
        rows = [[f"{u['name']} ({u['clearance'] or '?'}, {fmt_rights(u['funcs'], '/')})"]
                + [self.mon.effective(u["id"], f["id"]) for f in files] for u in users]
        self.rebuild_tree(self.mac_eff, cols, rows, height=6)
        self.mac_load()

    def mac_pair(self):
        ui, fi = self.list_index(self.mac_ul), self.list_index(self.mac_fl)
        return (None, None) if ui is None or fi is None else (ui, fi)

    def mac_load(self):
        ui, fi = self.mac_pair()
        if ui is None:
            self.mac_progress.config(text="Выберите субъекта и файл.")
            return
        u, f = self.db.user(self.mac_uids[ui]), self.db.file(self.mac_fids[fi])
        self.mac_clear.set(u["clearance"] or "")
        for r, v in self.mac_funcs.items():
            v.set(r in u["funcs"])
        self.mac_label.set(f["label"])
        owner = u["id"] == f["owner"]
        self.mac_allowed.set(owner or self.db.perm(f["id"], u["id"]))
        self.mac_allowed_cb.config(state="disabled" if owner else "normal",
                                   text="файл доступен субъекту (разрешение «да»)" + (" - владелец" if owner else ""))
        self.mac_progress.config(text=f"Субъект {ui + 1} из {len(self.mac_uids)}, файл {fi + 1} из {len(self.mac_fids)}")

    def mac_assign(self, advance):
        ui, fi = self.mac_pair()
        if ui is None:
            messagebox.showerror("Ошибка", "Выберите субъекта и файл.", parent=self)
            return
        clearance, label = self.mac_clear.get(), self.mac_label.get()
        if clearance not in LEVELS or label not in LEVELS:
            messagebox.showerror("Недопустимое значение", "Уровень допуска и гриф - S1, S2 или S3.", parent=self)
            return
        if not self.admin_action("назначение прав и грифа"):
            return
        u, f = self.db.user(self.mac_uids[ui]), self.db.file(self.mac_fids[fi])
        funcs = "".join(r for r, v in self.mac_funcs.items() if v.get())
        self.db.update_user(u["id"], u["name"], clearance, funcs)
        self.db.set_label(f["id"], label)
        if u["id"] != f["owner"]:
            self.db.set_perm(f["id"], u["id"], self.mac_allowed.get())
        self.db.log(self.uid, "mac", f["name"], "назначение прав и грифа", "выполнено",
                    f"субъект {u['name']}: допуск {clearance}, функции {fmt_rights(funcs, '/')}; "
                    f"файл: гриф {label}, доступен: {'да' if self.mac_allowed.get() else 'нет'}")
        if advance:
            fi += 1
            if fi == len(self.mac_fids):
                fi, ui = 0, ui + 1
            if ui == len(self.mac_uids):
                self.refresh_mac()
                messagebox.showinfo("Назначение прав", "Все права и грифы назначены, все файлы рассмотрены,\n"
                                                       "список пользователей исчерпан.", parent=self)
                return
            for lb, i in ((self.mac_ul, ui), (self.mac_fl, fi)):
                lb.selection_clear(0, "end")
                lb.selection_set(i)
        self.refresh_mac()

    def mac_strict(self):
        if not self.admin_action("правило записи"):
            self.v_strict.set(self.mon.strict())
            return
        self.db.set("strict_write", "1" if self.v_strict.get() else "0")
        self.db.log(self.uid, "mac", None, "правило записи", "выполнено",
                    "писать только в файл с грифом выше" if self.v_strict.get() else "писать в файл с грифом не ниже")
        self.refresh_mac()

    # --- вкладка «Пользователи и атрибуты»
    def build_users_tab(self):
        t = self.tab_users
        ttk.Label(t, text="Атрибуты пользователей: роль, модель доступа, уровень допуска и разрешенные функции "
                          "(мандатная модель, Табл. 2). Пароли хранятся только в виде хэша scrypt с солью.",
                  wraplength=1080, justify="left").pack(anchor="w", pady=(0, 8))
        cols = {"id": ("ID", 60), "name": ("Имя", 170), "role": ("Роль", 120), "model": ("Модель доступа", 140),
                "clear": ("Уровень допуска", 120), "funcs": ("Разрешенные функции", 150),
                "files": ("Владелец файлов", 150), "changed": ("Пароль изменен", 150)}
        self.users_tree = self.make_tree(t, cols, height=14)
        btns = ttk.Frame(t)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Добавить пользователя", command=self.admin_add_user).pack(side="left")
        ttk.Button(btns, text="Изменить атрибуты", command=self.admin_edit_user).pack(side="left", padx=6)
        ttk.Button(btns, text="Сменить пароль", command=self.admin_reset_password).pack(side="left")
        ttk.Button(btns, text="Удалить", command=self.admin_delete_user).pack(side="left", padx=6)

    def refresh_users(self):
        t = self.users_tree
        sel = t.selection()
        t.delete(*t.get_children())
        for u in self.db.users():
            mac = u["model"] == "mac"
            t.insert("", "end", iid=u["id"], values=(
                u["id"], u["name"], ROLES[u["role"]], MODELS.get(u["model"], "все (управление)"),
                (u["clearance"] or "не назначен") if mac else "-", fmt_rights(u["funcs"], "/") if mac else "-",
                ", ".join(self.db.owned_files(u["id"])) or "-", u["changed"]))
        if sel and t.exists(sel[0]):
            t.selection_set(sel[0])

    def selected_user(self):
        sel = self.users_tree.selection()
        if not sel:
            messagebox.showerror("Ошибка", "Выберите пользователя в таблице.", parent=self)
            return None
        return sel[0]

    def admin_add_user(self):
        dlg = UserDialog(self)
        if not dlg.result or not self.admin_action("добавление пользователя"):
            return
        d = dlg.result
        self.db.add_user(d["id"], d["name"], d["pass"], "user", d["model"], d["clearance"], d["funcs"])
        self.db.log(self.uid, d["model"], None, "добавление пользователя", "выполнено", f"{d['id']} {d['name']}")
        self.refresh_admin()

    def admin_edit_user(self):
        uid = self.selected_user()
        if not uid:
            return
        dlg = UserDialog(self, self.db.user(uid))
        if not dlg.result or not self.admin_action("атрибуты пользователя"):
            return
        d = dlg.result
        self.db.update_user(uid, d["name"], d["clearance"], d["funcs"])
        self.db.log(self.uid, d["model"], None, "атрибуты пользователя", "выполнено",
                    f"{uid}: имя {d['name']}, допуск {d['clearance'] or '-'}, функции {fmt_rights(d['funcs'], '/')}")
        self.refresh_admin()

    def admin_reset_password(self):
        uid = self.selected_user()
        if not uid:
            return
        dlg = PasswordDialog(self, f"Новый пароль для ID {uid}")
        if dlg.result and self.admin_action("смена пароля"):
            self.db.set_password(uid, dlg.result[1])
            self.db.log(self.uid, None, None, "смена пароля", "выполнено", f"пользователю {uid}")
            self.refresh_users()
            messagebox.showinfo("Пароль", "Пароль изменен: сформированы новая соль и новый хэш.", parent=self)

    def admin_delete_user(self):
        uid = self.selected_user()
        if not uid:
            return
        if uid == self.uid:
            messagebox.showerror("Ошибка", "Нельзя удалить собственную учетную запись.", parent=self)
            return
        owned = self.db.owned_files(uid)
        if owned:
            messagebox.showerror("Ошибка", f"Пользователь владеет файлами: {', '.join(owned)}.\n"
                                           "Сначала удалите эти файлы.", parent=self)
            return
        if messagebox.askyesno("Удаление", f"Удалить пользователя {uid}?", parent=self) and \
                self.admin_action("удаление пользователя"):
            self.db.delete_user(uid)
            self.db.log(self.uid, None, None, "удаление пользователя", "выполнено", uid)
            self.refresh_admin()

    # --- вкладка «Журнал обращений»
    def build_log_tab(self):
        t = self.tab_log
        ttk.Label(t, text="Все обращения к файлам и действия администратора (решения монитора обращений).",
                  foreground="#555").pack(anchor="w", pady=(0, 6))
        cols = {"time": ("Время", 140), "uid": ("ID", 50), "model": ("Модель", 125), "obj": ("Объект", 90),
                "action": ("Действие", 160), "result": ("Результат", 90), "reason": ("Причина / детали", 520)}
        self.log_tree = self.make_tree(t, cols, height=20)

    def refresh_log(self):
        t = self.log_tree
        t.delete(*t.get_children())
        for r in self.db.con.execute("SELECT * FROM access_log ORDER BY n DESC LIMIT 500"):
            t.insert("", "end", values=(r["time"], r["uid"] or "-", MODELS.get(r["model"], "-"), r["object"] or "-",
                                        r["action"], r["result"], r["reason"] or ""),
                     tags=("deny",) if r["result"] == "отказ" else ())


# ---------------------------------------------------------------- окна и диалоги

class Dialog(tk.Toplevel):
    def __init__(self, parent, title):
        super().__init__(parent)
        self.app = parent
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        self.body = ttk.Frame(self, padding=16)
        self.body.pack(fill="both", expand=True)

    def run(self, focus):
        focus.focus()
        self.grab_set()
        self.wait_window()


class PasswordDialog(Dialog):
    def __init__(self, parent, title, ask_old=False):
        super().__init__(parent, title)
        f = self.body
        self.entries = []
        labels = (["Текущий пароль"] if ask_old else []) + ["Новый пароль (6 символов)", "Повтор пароля"]
        for i, text in enumerate(labels):
            ttk.Label(f, text=text + ":").grid(row=i, column=0, sticky="w")
            e = ttk.Entry(f, width=20, show="*")
            e.grid(row=i, column=1, padx=(8, 0), pady=3)
            self.entries.append(e)
        self.ask_old = ask_old
        ttk.Button(f, text="OK", command=self.ok).grid(row=len(labels), column=0, columnspan=2, pady=(10, 0))
        self.run(self.entries[0])

    def ok(self):
        vals = [e.get().strip() for e in self.entries]
        old = vals[0] if self.ask_old else None
        new, new2 = vals[-2], vals[-1]
        if not pass_ok(new):
            messagebox.showerror("Ошибка", "Пароль - 6 символов: латинские буквы и цифры.", parent=self)
        elif new != new2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.", parent=self)
        elif self.ask_old and old == new:
            messagebox.showerror("Ошибка", "Новый пароль совпадает с текущим.", parent=self)
        else:
            self.result = (old, new)
            self.destroy()


class UserDialog(Dialog):
    """Добавление пользователя или изменение его атрибутов (имя, уровень допуска, функции)."""

    def __init__(self, parent, user=None):
        super().__init__(parent, "Атрибуты пользователя" if user else "Новый пользователь")
        self.user = user
        f = self.body
        self.e_id, self.e_name, self.e_pass = ttk.Entry(f, width=28), ttk.Entry(f, width=28), ttk.Entry(f, width=28)
        self.v_model = tk.StringVar(value=MODELS.get(user["model"], "-") if user else MODELS["dac"])
        self.v_clear = tk.StringVar(value=(user["clearance"] or "") if user else "")
        self.v_funcs = {r: tk.BooleanVar(value=bool(user) and r in user["funcs"]) for r in OPS}
        rows = [("ID (4 цифры)", self.e_id), ("Имя", self.e_name)]
        if not user:
            rows.append(("Пароль (6 символов)", self.e_pass))
        for i, (text, w) in enumerate(rows):
            ttk.Label(f, text=text + ":").grid(row=i, column=0, sticky="w")
            w.grid(row=i, column=1, sticky="w", padx=(8, 0), pady=3)
        r = len(rows)
        ttk.Label(f, text="Модель доступа:").grid(row=r, column=0, sticky="w")
        self.cb_model = ttk.Combobox(f, textvariable=self.v_model, values=list(MODELS.values()), state="readonly",
                                     width=16)
        self.cb_model.grid(row=r, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(f, text="Уровень допуска (MAC):").grid(row=r + 1, column=0, sticky="w")
        self.cb_clear = ttk.Combobox(f, textvariable=self.v_clear, values=LEVELS, state="readonly", width=6)
        self.cb_clear.grid(row=r + 1, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(f, text="Функции (MAC):").grid(row=r + 2, column=0, sticky="w")
        fr = ttk.Frame(f)
        fr.grid(row=r + 2, column=1, sticky="w", padx=(8, 0), pady=3)
        self.cb_funcs = [ttk.Checkbutton(fr, text=op, variable=v) for op, v in self.v_funcs.items()]
        for cb in self.cb_funcs:
            cb.pack(side="left", padx=(0, 6))
        ttk.Button(f, text="Сохранить", command=self.ok).grid(row=r + 3, column=0, columnspan=2, pady=(10, 0))
        if user:
            self.e_id.insert(0, user["id"])
            self.e_id.config(state="disabled")
            self.e_name.insert(0, user["name"])
            self.cb_model.config(state="disabled")      # модель пользователя не меняется
        self.cb_model.bind("<<ComboboxSelected>>", lambda e: self.model_changed())
        self.model_changed()
        self.run(self.e_name if user else self.e_id)

    def model(self):
        if self.user:                                   # у администратора модели нет (None)
            return self.user["model"]
        return "mac" if self.v_model.get() == MODELS["mac"] else "dac"

    def model_changed(self):
        mac = self.model() == "mac"
        self.cb_clear.config(state="readonly" if mac else "disabled")
        for cb in self.cb_funcs:
            cb.config(state="normal" if mac else "disabled")

    def ok(self):
        d = {"id": self.e_id.get().strip(), "name": " ".join(self.e_name.get().split()),
             "pass": self.e_pass.get().strip(), "model": self.model()}
        mac = d["model"] == "mac"
        d["clearance"] = self.v_clear.get() if mac and self.v_clear.get() else None
        d["funcs"] = "".join(r for r, v in self.v_funcs.items() if v.get()) if mac else ""
        errors = []
        db = self.app.db
        if not self.user:
            if not re.fullmatch(RE_ID, d["id"]):
                errors.append("ID - ровно 4 цифры")
            elif d["id"] == ADMIN_ID or db.user(d["id"]):
                errors.append(f"ID {d['id']} уже занят")
            if not pass_ok(d["pass"]):
                errors.append("пароль - 6 символов: латинские буквы и цифры (и те, и другие)")
        if not re.fullmatch(RE_NAME, d["name"]):
            errors.append("имя - от 1 до 30 символов: буквы, цифры, пробел, «_», «-»")
        elif any(u["name"].lower() == d["name"].lower() and (not self.user or u["id"] != self.user["id"])
                 for u in db.users()):
            errors.append(f"имя {d['name']} уже занято")
        if mac and not d["clearance"]:
            errors.append("субъекту мандатной модели нужен уровень допуска S1, S2 или S3")
        if errors:
            messagebox.showerror("Недопустимые значения", "\n".join("• " + e for e in errors), parent=self)
            return
        self.result = d
        self.destroy()


class MacFileDialog(Dialog):
    """Табл. 3: создание файла субъектом (гриф не выше своего, доступность для других субъектов)
    или изменение атрибутов своего файла владельцем."""

    def __init__(self, parent, fid=None):
        super().__init__(parent, "Атрибуты файла" if fid else "Новый файл (мандатный каталог)")
        self.fid = fid
        db = parent.db
        me = db.user(parent.uid)
        f = db.file(fid) if fid else None
        b = self.body
        ttk.Label(b, text="Имя файла:").grid(row=0, column=0, sticky="w")
        self.e_name = ttk.Entry(b, width=26)
        self.e_name.grid(row=0, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(b, text="Гриф файла:").grid(row=1, column=0, sticky="w")
        self.v_label = tk.StringVar(value=f["label"] if f else me["clearance"])
        # в списке все грифы: выбор грифа выше своего уровня - недопустимое значение, его отклоняет проверка
        ttk.Combobox(b, textvariable=self.v_label, values=LEVELS, state="readonly", width=6).grid(
            row=1, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(b, text=f"ваш уровень допуска: {me['clearance']}; гриф - не выше него"
                          + ("; понизить гриф может только администратор" if f else ""),
                  foreground="#555").grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(b, text="Доступность файла для субъектов:").grid(row=3, column=0, columnspan=2, sticky="w",
                                                                   pady=(8, 2))
        self.v_perm = {}
        r = 4
        for u in db.users("mac"):
            if u["id"] == me["id"]:
                continue
            v = tk.BooleanVar(value=bool(f) and db.perm(fid, u["id"]))
            ttk.Checkbutton(b, text=f"{u['name']} (ID {u['id']}, допуск {u['clearance'] or '?'})",
                            variable=v).grid(row=r, column=0, columnspan=2, sticky="w")
            self.v_perm[u["id"]] = v
            r += 1
        ttk.Button(b, text="Сохранить" if fid else "Создать", command=self.ok).grid(row=r, column=0, columnspan=2,
                                                                                    pady=(10, 0))
        b.columnconfigure(1, weight=1)
        if f:
            self.e_name.insert(0, f["name"])
            self.e_name.config(state="disabled")
        self.run(self.e_name)

    def ok(self):
        perms = {uid: v.get() for uid, v in self.v_perm.items()}
        try:
            if self.fid:
                self.app.fs.set_mac_attrs(self.app.uid, self.fid, self.v_label.get(), perms)
                self.result = self.fid
            else:
                self.result = self.app.fs.create(self.app.uid, self.e_name.get().strip(), self.v_label.get(), perms)
        except ValueError as e:
            messagebox.showerror("Недопустимое значение", str(e), parent=self)
            return
        except AccessDenied as e:
            messagebox.showerror("Ошибка доступа", str(e), parent=self)
            return
        self.destroy()


class DelegateDialog(Dialog):
    """DAC: передоверенное право A - назначение прав на файл другим пользователям."""

    def __init__(self, parent, fid):
        db = parent.db
        self.fid, f = fid, db.file(fid)
        super().__init__(parent, f"Передача прав на файл {f['name']}")
        self.own = db.dac_rights(fid, parent.uid)
        self.others = [u for u in db.users("dac") if u["id"] != parent.uid]
        b = self.body
        ttk.Label(b, text=f"Ваши права на {f['name']}: {fmt_rights(self.own)}.\nНазначать и отзывать можно только "
                          f"права, которыми обладаете сами; право A передает только администратор.",
                  justify="left", foreground="#555").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(b, text="Пользователь:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.v_user = tk.StringVar()
        cb = ttk.Combobox(b, textvariable=self.v_user, state="readonly", width=26,
                          values=[f"{u['name']} (ID {u['id']})" for u in self.others])
        cb.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(8, 0))
        cb.bind("<<ComboboxSelected>>", lambda e: self.load())
        fr = ttk.Frame(b)
        fr.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.v_rights = {r: tk.BooleanVar() for r in OPS}
        for r, v in self.v_rights.items():
            ttk.Checkbutton(fr, text=f"{r} - {DAC_RIGHTS[r]}", variable=v).pack(side="left", padx=(0, 8))
        ttk.Button(b, text="Применить", command=self.ok).grid(row=3, column=0, columnspan=2, pady=(10, 0))
        b.columnconfigure(1, weight=1)
        if self.others:
            cb.current(0)
            self.load()
        self.run(cb)

    def target(self):
        i = [f"{u['name']} (ID {u['id']})" for u in self.others].index(self.v_user.get())
        return self.others[i]["id"]

    def load(self):
        rights = self.app.db.dac_rights(self.fid, self.target())
        for r, v in self.v_rights.items():
            v.set(r in rights)

    def ok(self):
        if not self.v_user.get():
            return
        rights = "".join(r for r, v in self.v_rights.items() if v.get())
        try:
            self.app.fs.delegate(self.app.uid, self.fid, self.target(), rights)
        except ValueError as e:
            messagebox.showerror("Недопустимое значение", str(e), parent=self)
            return
        except AccessDenied as e:
            messagebox.showerror("Ошибка доступа", str(e), parent=self)
            self.load()
            return
        messagebox.showinfo("Передача прав", "Права назначены.", parent=self)


class ProtocolWindow(tk.Toplevel):
    """Протокол проверки по алгоритму рис. 1, 2: для каждого файла применяются допустимые и
    недопустимые права; когда все права и все файлы проверены - выход без нарушений."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Протокол проверки прав")
        self.transient(app)
        f = ttk.Frame(self, padding=12)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Результаты применения прав в этом сеансе (кнопки «Читать», «Копировать», «Редактировать»)",
                  foreground="#555").pack(anchor="w", pady=(0, 6))
        cols = {"file": ("Файл", 90), "R": ("R - читать", 150), "C": ("C - копировать", 150),
                "E": ("E - редактировать", 150)}
        self.tree = app.make_tree(f, cols, height=8)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_reasons())
        self.reasons = ttk.Label(f, text="", justify="left", wraplength=560)
        self.reasons.pack(anchor="w", pady=(6, 0))
        self.summary = ttk.Label(f, text="", justify="left", wraplength=560, font=("", 11, "bold"))
        self.summary.pack(anchor="w", pady=(6, 0))
        bb = ttk.Frame(f)
        bb.pack(anchor="w", pady=(8, 0))
        ttk.Button(bb, text="Проверить оставшиеся права автоматически", command=self.auto).pack(side="left")
        ttk.Button(bb, text="Очистить протокол", command=self.reset).pack(side="left", padx=6)
        ttk.Button(bb, text="Закрыть", command=self.destroy).pack(side="left")
        self.refresh()

    def files(self):
        return self.app.db.files(self.app.model)

    def refresh(self):
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        total = done = good = bad = 0
        for f in self.files():
            cells = []
            for op in OPS:
                res = self.app.tried.get((f["id"], op))
                total += 1
                if res is None:
                    cells.append("· не проверено")
                    continue
                done += 1
                if res[0]:
                    good += 1
                    cells.append("✔ выполнено")
                else:
                    bad += 1
                    cells.append("✖ ошибка доступа")
            self.tree.insert("", "end", iid=str(f["id"]), values=[f["name"]] + cells)
        if sel and self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])
        text = f"Проверено {done} из {total}: допустимых (выполнено) - {good}, недопустимых (ошибка доступа) - {bad}."
        if total and done == total:
            text += "\nВсе права проверены, все файлы проверены - выход без нарушений."
        self.summary.config(text=text, foreground="#070" if total and done == total else "#000")
        self.show_reasons()

    def show_reasons(self):
        sel = self.tree.selection()
        if not sel:
            self.reasons.config(text="Выберите файл, чтобы увидеть причины решений монитора.")
            return
        fid = int(sel[0])
        lines = []
        for op in OPS:
            res = self.app.tried.get((fid, op))
            lines.append(f"{op}: " + (res[1] if res else "не проверено"))
        self.reasons.config(text="\n".join(lines))

    def auto(self):
        app = self.app
        for f in self.files():
            for op in OPS:
                if (f["id"], op) in app.tried:
                    continue
                try:
                    app.mon.check(app.uid, f["id"], op, note="автопроверка")
                    app.tried[(f["id"], op)] = (True, app.mon.decide(app.uid, f["id"], op)[1])
                except AccessDenied as e:
                    app.tried[(f["id"], op)] = (False, str(e))
        self.refresh()

    def reset(self):
        self.app.tried.clear()
        self.refresh()


# ---------------------------------------------------------------- запуск

def main():
    App(DB()).mainloop()


if __name__ == "__main__":
    main()
