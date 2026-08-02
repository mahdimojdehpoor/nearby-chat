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

# اهداف قابل انتخاب کاربر هنگام ثبت‌نام
GOAL_LABELS = {
    "friend": "دوستیابی / آشنایی عمومی",
    "marriage": "آشنایی برای ازدواج",
    "job": "فرصت شغلی / همکاری",
    "consult": "مشورت / ایده‌پردازی",
}

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
                goal TEXT DEFAULT 'friend',
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

            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blocker_id INTEGER NOT NULL,
                blocked_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(blocker_id, blocked_id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                reported_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
            """
        )
        db.commit()
        # افزودن ستون goal برای دیتابیس‌های قدیمی‌تر که از قبل ساخته شده‌اند
        cols = [row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()]
        if "goal" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN goal TEXT DEFAULT 'friend'")
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


def blocked_pair_ids(user_id):
    """آی‌دی‌هایی که کاربر بلاک کرده یا کاربر را بلاک کرده‌اند (در هر دو جهت)"""
    db = get_db()
    rows = db.execute(
        "SELECT blocker_id, blocked_id FROM blocks WHERE blocker_id = ? OR blocked_id = ?",
        (user_id, user_id),
    ).fetchall()
    ids = set()
    for r in rows:
        ids.add(r["blocker_id"])
        ids.add(r["blocked_id"])
    ids.discard(user_id)
    return ids


def is_blocked_either_way(user_a, user_b):
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)",
        (user_a, user_b, user_b, user_a),
    ).fetchone()
    return row is not None


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
        goal = request.form.get("goal", "friend")
        if goal not in GOAL_LABELS:
            goal = "friend"

        if not username or not password:
            error = "نام کاربری و رمز عبور الزامی است."
        else:
            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                error = "این نام کاربری قبلاً استفاده شده است."
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash, bio, goal, last_seen) VALUES (?, ?, ?, ?, ?)",
                    (username, generate_password_hash(password), bio, goal, time.time()),
                )
                db.commit()
                user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                session["user_id"] = user["id"]
                return redirect(url_for("nearby"))
    return render_template("register.html", error=error, goals=GOAL_LABELS)


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
    return render_template("nearby.html", user=user, goals=GOAL_LABELS)


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
    goal_filter = request.args.get("goal", "all")
    db = get_db()
    me = current_user()
    if me["lat"] is None or me["lng"] is None:
        return jsonify({"ok": False, "error": "موقعیت مکانی شما هنوز ثبت نشده است."}), 400

    excluded = blocked_pair_ids(me["id"])

    rows = db.execute(
        "SELECT id, username, bio, goal, lat, lng, last_seen FROM users WHERE id != ? AND lat IS NOT NULL AND lng IS NOT NULL",
        (me["id"],),
    ).fetchall()

    now = time.time()
    result = []
    for r in rows:
        if r["id"] in excluded:
            continue
        if goal_filter != "all" and r["goal"] != goal_filter:
            continue
        dist = haversine_km(me["lat"], me["lng"], r["lat"], r["lng"])
        if dist <= radius_km:
            result.append(
                {
                    "id": r["id"],
                    "username": r["username"],
                    "bio": r["bio"],
                    "goal": r["goal"],
                    "goal_label": GOAL_LABELS.get(r["goal"], r["goal"]),
                    "distance_km": round(dist, 2),
                    "online": (now - r["last_seen"]) < ONLINE_THRESHOLD_SECONDS,
                }
            )
    result.sort(key=lambda x: x["distance_km"])
    return jsonify({"ok": True, "users": result})


# ---------------------------------------------------------------------------
# گزارش و بلاک‌کردن کاربر
# ---------------------------------------------------------------------------

@app.route("/api/block/<int:other_id>", methods=["POST"])
@login_required
def block_user(other_id):
    if other_id == session["user_id"]:
        return jsonify({"ok": False, "error": "نمی‌توانید خودتان را بلاک کنید."}), 400
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)",
        (session["user_id"], other_id, time.time()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/unblock/<int:other_id>", methods=["POST"])
@login_required
def unblock_user(other_id):
    db = get_db()
    db.execute(
        "DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?",
        (session["user_id"], other_id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/blocked")
@login_required
def blocked_list():
    db = get_db()
    rows = db.execute(
        """SELECT u.id, u.username FROM blocks b
           JOIN users u ON u.id = b.blocked_id
           WHERE b.blocker_id = ?""",
        (session["user_id"],),
    ).fetchall()
    return render_template("blocked.html", blocked_users=rows)


@app.route("/api/report/<int:other_id>", methods=["POST"])
@login_required
def report_user(other_id):
    data = request.get_json(force=True) or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify({"ok": False, "error": "دلیل گزارش را بنویسید."}), 400
    db = get_db()
    db.execute(
        "INSERT INTO reports (reporter_id, reported_id, reason, created_at) VALUES (?, ?, ?, ?)",
        (session["user_id"], other_id, reason, time.time()),
    )
    db.commit()
    return jsonify({"ok": True})


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
    blocked = is_blocked_either_way(session["user_id"], other_id)
    return render_template(
        "chat.html", other=other, room=room_name(session["user_id"], other_id), blocked=blocked
    )


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
    try:
        a, b = room.split("_")
        other_id = int(b) if int(a) == session["user_id"] else int(a)
        if is_blocked_either_way(session["user_id"], other_id):
            return jsonify({"ok": False, "error": "این ارتباط بلاک شده است."}), 403
    except (ValueError, IndexError):
        pass
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
