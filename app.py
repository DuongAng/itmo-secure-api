"""
Secure REST API (Работа 1 — Информационная безопасность, ИТМО).

Простой, но защищённый веб-API на Flask, демонстрирующий меры защиты
из OWASP Top 10:
  * A03:2021 Injection        -> параметризованные SQL-запросы (prepared statements)
  * A03:2021 XSS              -> экранирование пользовательского ввода (markupsafe.escape)
  * A07:2021 Auth failures    -> JWT-токены + хэширование паролей bcrypt

Эндпоинты:
  POST /auth/register  — регистрация пользователя (bcrypt-хэш пароля)
  POST /auth/login     — аутентификация, выдаёт JWT-токен
  GET  /api/data       — защищённый: список постов (нужен валидный JWT)
  POST /api/posts      — защищённый: создать пост (XSS-экранирование + parametrized SQL)
"""
import os
import sqlite3
import datetime
import functools

import bcrypt
import jwt
from flask import Flask, request, jsonify, g
from markupsafe import escape

# --- Конфигурация --------------------------------------------------------
# Секрет для подписи JWT берётся ТОЛЬКО из окружения (в репозиторий не коммитим).
# Значение по умолчанию используется лишь для локального запуска/тестов.
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-change-me")
JWT_ALG = "HS256"
JWT_TTL_MIN = 60  # срок жизни токена, минут
DB_PATH = os.environ.get("DB_PATH", "app.db")

app = Flask(__name__)


# --- Работа с БД ---------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            author   TEXT NOT NULL,
            title    TEXT NOT NULL,
            content  TEXT NOT NULL,
            created  TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


# --- Аутентификация ------------------------------------------------------
def make_token(username: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=JWT_TTL_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def require_auth(view):
    """Middleware-декоратор: пропускает только с валидным JWT в заголовке
    Authorization: Bearer <token>."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="Отсутствует или неверный заголовок Authorization"), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except jwt.ExpiredSignatureError:
            return jsonify(error="Срок действия токена истёк"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Недействительный токен"), 401
        g.user = payload["sub"]
        return view(*args, **kwargs)

    return wrapper


# --- Эндпоинты -----------------------------------------------------------
@app.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(error="Требуются поля username и password"), 400
    if len(password) < 8:
        return jsonify(error="Пароль должен быть не короче 8 символов"), 400

    # Пароль НИКОГДА не хранится в открытом виде — только bcrypt-хэш (с солью).
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        # Параметризованный запрос: значения передаются отдельно от SQL-текста,
        # поэтому SQL-инъекция через username невозможна.
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Пользователь уже существует"), 409
    return jsonify(message="Пользователь зарегистрирован", username=escape(username)), 201


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    # Параметризованный запрос — защита от SQLi.
    row = db.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Сравниваем хэши. Одинаковый ответ при неверном логине и неверном пароле,
    # чтобы не раскрывать, существует ли пользователь.
    if row is None or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return jsonify(error="Неверный логин или пароль"), 401

    return jsonify(token=make_token(username), token_type="Bearer")


@app.get("/api/data")
@require_auth
def api_data():
    """Защищённый эндпоинт: доступен только аутентифицированным пользователям."""
    db = get_db()
    rows = db.execute(
        "SELECT id, author, title, content, created FROM posts ORDER BY id DESC"
    ).fetchall()
    posts = [dict(r) for r in rows]
    return jsonify(user=g.user, count=len(posts), posts=posts)


@app.post("/api/posts")
@require_auth
def create_post():
    """Третий метод: создание поста. Демонстрирует одновременно
    параметризованный INSERT (SQLi) и экранирование вывода (XSS)."""
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    if not title or not content:
        return jsonify(error="Требуются поля title и content"), 400

    # Экранируем пользовательский ввод: теги вроде <script> превращаются в
    # безопасный текст (&lt;script&gt;) и не выполнятся в браузере клиента.
    safe_title = str(escape(title))
    safe_content = str(escape(content))

    db = get_db()
    created = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    cur = db.execute(
        "INSERT INTO posts (author, title, content, created) VALUES (?, ?, ?, ?)",
        (g.user, safe_title, safe_content, created),
    )
    db.commit()
    return jsonify(id=cur.lastrowid, title=safe_title, content=safe_content), 201


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    init_db()
    # debug=False: не раскрываем отладочную информацию в проде.
    app.run(host="127.0.0.1", port=5000, debug=False)
