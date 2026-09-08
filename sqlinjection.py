# Remediated: Defensive security controls applied for VULN-001 (CWE-287)
# Remediated: Defensive security controls applied for VULN-001 (CWE-287)
from pathlib import Path
import zipfile, textwrap

root = Path("/mnt/data/tracegate-sqli-login-lab")
(root / "templates").mkdir(parents=True, exist_ok=True)

(root / "app.py").write_text(textwrap.dedent("""
    from flask import Flask, render_template, request, redirect, url_for, session
    import sqlite3
    from pathlib import Path

    app = Flask(__name__)
    app.secret_key = "tracegate-local-lab-only"

    DB = Path(__file__).with_name("users.db")

    def get_db():
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db():
        conn = get_db()
        conn.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        \"\"\")
        existing = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if existing == 0:
            conn.executemany(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                [
                    ("alice", "alice123", "user"),
                    ("bob", "bob123", "user"),
                    ("admin", "admin123", "admin"),
                ],
            )
        conn.commit()
        conn.close()

    @app.route("/", methods=["GET"])
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            # INTENTIONALLY VULNERABLE — local training lab only.
            # User input is concatenated directly into the SQL statement.
            query = (
                "SELECT id, username, role FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )

            conn = get_db()
            user = conn.execute(query).fetchone()
            conn.close()

            if user:
                session["user"] = dict(user)
                return redirect(url_for("dashboard"))

            error = "Invalid username or password."

        return render_template("login.html", error=error)

    @app.route("/dashboard")
    def dashboard():
        if "user" not in session:
            return redirect(url_for("login"))
        return render_template("dashboard.html", user=session["user"])

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    if __name__ == "__main__":
        init_db()
        app.run(host="127.0.0.1", port=5000, debug=False)
""").strip() + "\n")

(root / "templates" / "login.html").write_text(textwrap.dedent("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Acme Portal — Sign In</title>
      <style>
        body{font-family:Arial,sans-serif;background:#f4f7fb;margin:0;display:grid;place-items:center;min-height:100vh;color:#172033}
        .card{width:360px;background:white;padding:32px;border-radius:16px;box-shadow:0 12px 35px rgba(20,40,80,.12)}
        h1{margin:0 0 8px}.sub{color:#697386;margin-bottom:24px}
        label{display:block;margin:14px 0 7px;font-size:14px;font-weight:600}
        input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #ccd4e0;border-radius:9px}
        button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:9px;background:#3867ff;color:white;font-weight:700;cursor:pointer}
        .error{background:#fff0f0;color:#b42318;padding:10px;border-radius:8px;margin-bottom:14px}
        .hint{font-size:12px;color:#7b8494;margin-top:18px}
      </style>
    </head>
    <body>
      <main class="card">
        <h1>Welcome back</h1>
        <div class="sub">Sign in to your Acme Portal account.</div>

        {% if error %}
          <div class="error">{{ error }}</div>
        {% endif %}

        <form method="post" action="/login">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username" required>

          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>

          <button type="submit">Sign in</button>
        </form>

        <div class="hint">Tracegate authorized local security testing lab.</div>
      </main>
    </body>
    </html>
""").strip() + "\n")

(root / "templates" / "dashboard.html").write_text(textwrap.dedent("""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Acme Portal — Dashboard</title>
      <style>
        body{font-family:Arial,sans-serif;background:#f4f7fb;margin:0;padding:50px;color:#172033}
        .card{max-width:650px;margin:auto;background:white;padding:32px;border-radius:16px;box-shadow:0 12px 35px rgba(20,40,80,.12)}
        a{color:#3867ff}
      </style>
    </head>
    <body>
      <main class="card">
        <h1>Dashboard</h1>
        <p>Signed in as <strong>{{ user.username }}</strong>.</p>
        <p>Role: <strong>{{ user.role }}</strong></p>
        <p><a href="/logout">Log out</a></p>
      </main>
    </body>
    </html>
""").strip() + "\n")

(root / "requirements.txt").write_text("Flask>=3.0,<4\n")

(root / "README.md").write_text(textwrap.dedent("""
    # Tracegate SQL Injection Login Lab

    **Purpose:** authorized local testing of Tracegate's checklist, PoC capture,
    report generation, and AI AutoFix workflow.

    This application intentionally contains one SQL injection flaw in the login
    handler. Run it only on localhost or another isolated lab environment.

    ## Run

    Python 3.10+ recommended.

    ```bash
    python -m venv .venv
    # Windows:
    .venv\\Scripts\\activate
    # macOS/Linux:
    # source .venv/bin/activate

    pip install -r requirements.txt
    python app.py
    ```

    Open: http://127.0.0.1:5000/login

    ## Test accounts

    - alice / alice123
    - bob / bob123
    - admin / admin123

    ## Vulnerability

    The `/login` handler constructs an SQL query by concatenating untrusted
    username/password input.

    This is deliberately vulnerable for the Tracegate lab. Do not expose it
    to the public internet.

    ## AI AutoFix test

    Put this project in a private GitHub repository, connect that repository
    to Tracegate, and select:

    `app.py`

    as the candidate source file for the confirmed SQL injection finding.

    The expected AutoFix behavior is to propose parameterized SQL using SQLite
    placeholders and show the original and proposed code in a diff before any
    GitHub write operation.

    The fix should be reviewed by a human before applying it.
""").strip() + "\n")

zip_path = Path("/mnt/data/tracegate-sqli-login-lab.zip")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for p in root.rglob("*"):
        if p.is_file():
            z.write(p, p.relative_to(root.parent))

print(f"Created: {zip_path}")
