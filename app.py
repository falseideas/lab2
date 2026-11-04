"""Deliberately vulnerable local OWASP lab. Do not expose to the internet."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import sqlite3
import html

HOST = "127.0.0.1"
PORT = 8000


def init_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
    db.executemany("INSERT INTO users VALUES (?, ?)", [
        ("admin", "lab_admin_password"),
        ("student", "student123"),
    ])
    db.commit()
    return db


DB = init_db()


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, text):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parts = urlsplit(self.path)
        params = parse_qs(parts.query)

        if parts.path == "/":
            self.respond(200, """<!doctype html><html lang='ru'><meta charset='utf-8'>
<title>OWASP Lab 2</title><h1>Учебный портал</h1>
<p>Только для локальной лаборатории. Сервер содержит преднамеренные уязвимости.</p>
<form action='/login' method='get'>
<label>Логин: <input name='username'></label>
<label>Пароль: <input name='password' type='password'></label>
<button>Войти</button></form>
<form action='/search' method='get'>
<label>Поиск: <input name='q'></label><button>Искать</button></form>
</html>""")
        elif parts.path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            # VULNERABILITY 1: SQL injection through string interpolation.
            sql = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                row = DB.execute(sql).fetchone()
            except sqlite3.Error:
                self.respond(400, "<h1>Ошибка запроса</h1>")
                return
            if row:
                self.respond(200, "<h1>LOGIN_OK</h1><p>Успешный вход</p>")
            else:
                self.respond(401, "<h1>LOGIN_FAILED</h1><p>Неверные данные</p>")
        elif parts.path == "/search":
            query = params.get("q", [""])[0]
            # VULNERABILITY 2: reflected XSS through unescaped HTML output.
            self.respond(200, f"<!doctype html><html lang='ru'><meta charset='utf-8'><h1>Поиск</h1><p>Вы искали: {query}</p></html>")
        else:
            self.respond(404, "<h1>Не найдено</h1>")


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"OWASP Lab running at http://{HOST}:{PORT} (Ctrl+C to stop)", flush=True)
    server.serve_forever()
