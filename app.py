"""
Nearby Chat - یک برنامه‌ی اجتماعی ساده برای چت با افراد نزدیک
--------------------------------------------------------------
Flask + SQLite. بدون وابستگی سنگین (بدون websocket) - چت با AJAX polling کار می‌کند.

اجرا:
    pip install -r requirements.txt
    python app.py
سپس مرورگر را باز کن: http://127.0.0.1:5000
"""

import math
import sqlite3
import time
from datetime import datetime
from functools import wraps

from flask import Flask, g, render_template, request, session, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = "nearby_chat.db"
ONLINE_THRESHOLD_SECONDS = 90  # اگر کاربر تا این مدت پینگ نزند، آفلاین در نظر گرفته می‌شود

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"


# ---------------------------------------------------------------------------
# دیتابیس
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                lat REAL,
                lng REAL,
                last_seen REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
            """
        )
        db.commit()


# ---------------------------------------------------------------------------
# ابزارها
# ---------------------------------------------------------------------------

def haversine_km(lat1, lng1, lat2, lng2):
    """فاصله‌ی بین دو نقطه جغرافیایی بر حسب کیلومتر"""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def room_name(user_id_a, user_id_b):
    a, b = sorted([int(user_id_a), int(user_id_b)])
    return f"{a}_{b}"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if not session.get("user_id"):
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


# ---------------------------------------------------------------------------
# صفحات (Auth)
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        bio = request.form.get("bio", "").strip()

        if not username or not password:
            error = "نام کاربری و رمز عبور الزامی است."
        else:
            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                error = "این نام کاربری قبلاً استفاده شده است."
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash, bio, last_seen) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), bio, time.time()),
                )
                db.commit()
                user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                session["user_id"] = user["id"]
                return redirect(url_for("nearby"))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            error = "نام کاربری یا رمز عبور اشتباه است."
        else:
            session["user_id"] = user["id"]
            db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (time.time(), user["id"]))
            db.commit()
            return redirect(url_for("nearby"))
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# صفحه اصلی: لیست افراد نزدیک
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def nearby():
    user = current_user()
    return render_template("nearby.html", user=user)


@app.route("/api/location", methods=["POST"])
@login_required
def update_location():
    data = request.get_json(force=True) or {}
    lat, lng = data.get("lat"), data.get("lng")
    if lat is None or lng is None:
        return jsonify({"ok": False, "error": "lat/lng missing"}), 400
    db = get_db()
    db.execute(
        "UPDATE users SET lat = ?, lng = ?, last_seen = ? WHERE id = ?",
        (float(lat), float(lng), time.time(), session["user_id"]),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/nearby")
@login_required
def api_nearby():
    radius_km = float(request.args.get("radius_km", 10))
    db = get_db()
    me = current_user()
    if me["lat"] is None or me["lng"] is None:
        return jsonify({"ok": False, "error": "موقعیت مکانی شما هنوز ثبت نشده است."}), 400

    rows = db.execute(
        "SELECT id, username, bio, lat, lng, last_seen FROM users WHERE id != ? AND lat IS NOT NULL AND lng IS NOT NULL",
        (me["id"],),
    ).fetchall()

    now = time.time()
    result = []
    for r in rows:
        dist = haversine_km(me["lat"], me["lng"], r["lat"], r["lng"])
        if dist <= radius_km:
            result.append(
                {
                    "id": r["id"],
                    "username": r["username"],
                    "bio": r["bio"],
                    "distance_km": round(dist, 2),
                    "online": (now - r["last_seen"]) < ONLINE_THRESHOLD_SECONDS,
                }
            )
    result.sort(key=lambda x: x["distance_km"])
    return jsonify({"ok": True, "users": result})


# ---------------------------------------------------------------------------
# چت
# ---------------------------------------------------------------------------

@app.route("/chat/<int:other_id>")
@login_required
def chat(other_id):
    db = get_db()
    other = db.execute("SELECT * FROM users WHERE id = ?", (other_id,)).fetchone()
    if other is None:
        return redirect(url_for("nearby"))
    return render_template("chat.html", other=other, room=room_name(session["user_id"], other_id))


@app.route("/api/messages/<room>", methods=["GET"])
@login_required
def get_messages(room):
    since = float(request.args.get("since", 0))
    db = get_db()
    rows = db.execute(
        """SELECT m.id, m.sender_id, u.username AS sender_name, m.body, m.created_at
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.room = ? AND m.created_at > ?
           ORDER BY m.created_at ASC""",
        (room, since),
    ).fetchall()
    return jsonify(
        {
            "ok": True,
            "messages": [
                {
                    "id": r["id"],
                    "sender_id": r["sender_id"],
                    "sender_name": r["sender_name"],
                    "body": r["body"],
                    "created_at": r["created_at"],
                    "is_me": r["sender_id"] == session["user_id"],
                }
                for r in rows
            ],
        }
    )


@app.route("/api/messages/<room>", methods=["POST"])
@login_required
def post_message(room):
    data = request.get_json(force=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"ok": False, "error": "empty message"}), 400
    db = get_db()
    now = time.time()
    db.execute(
        "INSERT INTO messages (room, sender_id, body, created_at) VALUES (?, ?, ?, ?)",
        (room, session["user_id"], body, now),
    )
    db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, session["user_id"]))
    db.commit()
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
