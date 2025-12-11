import os
import uuid
import datetime as dt
import bcrypt
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# --- Konfigurasi dasar ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "ganti-ini-dengan-secret-yang-lebih-kuat"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)


# --- Model Database ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    # untuk fitur cooldown login
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    lock_until = db.Column(db.DateTime, nullable=True)

    files = db.relationship("UserFile", backref="owner", lazy=True)


class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)  # nama file di server
    mimetype = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    description = db.Column(db.Text)  # contoh data teks/komentar


# --- Helper function ---

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# --- Routes ---

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not password:
            flash("Username dan password wajib diisi.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Konfirmasi password tidak cocok.", "danger")
            return redirect(url_for("register"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username sudah digunakan.", "danger")
            return redirect(url_for("register"))

        # HASH PASSWORD menggunakan bcrypt
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()

        flash("Registrasi berhasil. Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()

        # 1. Kalau user ada, cek apakah sedang dalam masa cooldown
        if user and user.lock_until:
            now = dt.datetime.utcnow()
            if now < user.lock_until:
                remaining = user.lock_until - now
                remaining_minutes = int(remaining.total_seconds() // 60) or 1
                flash(
                    f"Terlalu banyak percobaan login gagal. "
                    f"Silakan coba lagi sekitar {remaining_minutes} menit lagi.",
                    "warning",
                )
                return redirect(url_for("login"))

        # 2. Kalau user tidak ada ATAU password salah
        if (not user) or (not bcrypt.checkpw(
            password.encode("utf-8"),
            user.password_hash.encode("utf-8") if user else b""
        )):
            # Kalau user tidak ada, cukup kasih pesan umum
            if not user:
                flash("Username atau password salah.", "danger")
                return redirect(url_for("login"))

            # user ada tapi password salah -> naikkan counter
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            attempts_before_lock = 3  # percobaan salah yang diizinkan
            wait_minutes = 0
            now = dt.datetime.utcnow()

            if user.failed_login_attempts >= attempts_before_lock:
                # Salah ke-3 -> 5 menit
                # Salah ke-4 -> 10 menit
                # Salah ke-5 -> 20 menit, dst (×2)
                extra_index = user.failed_login_attempts - attempts_before_lock
                wait_minutes = 5 * (2 ** extra_index)
                user.lock_until = now + dt.timedelta(minutes=wait_minutes)
                db.session.commit()

                flash(
                    f"Username atau password salah. "
                    f"Terlalu banyak percobaan gagal. Coba lagi dalam {wait_minutes} menit.",
                    "warning",
                )
            else:
                # Masih di bawah batas -> beritahu sisa percobaan
                remaining = attempts_before_lock - user.failed_login_attempts
                db.session.commit()
                flash(
                    f"Username atau password salah. "
                    f"Sisa percobaan sebelum jeda: {remaining} kali.",
                    "danger",
                )

            return redirect(url_for("login"))

        # 3. Kalau password benar -> reset counter & lock
        user.failed_login_attempts = 0
        user.lock_until = None
        db.session.commit()

        session["user_id"] = user.id
        session["is_admin"] = user.is_admin
        flash("Login berhasil.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    user_files = UserFile.query.filter_by(
        user_id=user.id
    ).order_by(UserFile.uploaded_at.desc()).all()
    return render_template("dashboard.html", user=user, files=user_files)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    user = get_current_user()

    if request.method == "POST":
        description = request.form.get("description", "").strip()
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("Tidak ada file yang dipilih.", "danger")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("Tipe file tidak diizinkan.", "danger")
            return redirect(url_for("upload"))

        original_filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{original_filename}"

        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(user.id))
        os.makedirs(user_folder, exist_ok=True)

        file_path = os.path.join(user_folder, unique_name)
        file.save(file_path)

        user_file = UserFile(
            user_id=user.id,
            original_filename=original_filename,
            stored_filename=unique_name,
            mimetype=file.mimetype,
            description=description,
        )
        db.session.add(user_file)
        db.session.commit()

        flash("File berhasil di-upload.", "success")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    user = get_current_user()
    user_file = UserFile.query.get_or_404(file_id)

    # pemilik boleh download, admin boleh download semua
    if (not user.is_admin) and (user_file.user_id != user.id):
        abort(403)

    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(user_file.user_id))
    return send_from_directory(
        user_folder,
        user_file.stored_filename,
        as_attachment=True,
        download_name=user_file.original_filename,
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    user = get_current_user()
    user_file = UserFile.query.get_or_404(file_id)

    # Authorization: pemilik atau admin
    if (not user.is_admin) and (user_file.user_id != user.id):
        abort(403)

    # Hapus file fisik di folder uploads/<user_id>/
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(user_file.user_id))
    file_path = os.path.join(user_folder, user_file.stored_filename)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            # kalau gagal remove, lanjut hapus metadata saja
            pass

    # Hapus record di database
    db.session.delete(user_file)
    db.session.commit()

    flash("File berhasil dihapus.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    # Statistik sederhana
    total_users = User.query.count()
    total_files = UserFile.query.count()

    # Data untuk tabel
    users = User.query.order_by(User.id).all()
    files = (
        db.session.query(UserFile, User.username)
        .join(User, UserFile.user_id == User.id)
        .order_by(UserFile.uploaded_at.desc())
        .all()
    )

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_files=total_files,
        users=users,
        files=files,
    )


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    current = get_current_user()
    user = User.query.get_or_404(user_id)

    # cegah admin menghapus dirinya sendiri
    if current.id == user.id:
        flash("Admin tidak boleh menghapus dirinya sendiri.", "warning")
        return redirect(url_for("admin_dashboard"))

    # Hapus semua file fisik milik user ini
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(user.id))
    if os.path.exists(user_folder):
        for fname in os.listdir(user_folder):
            fpath = os.path.join(user_folder, fname)
            if os.path.isfile(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass
        try:
            os.rmdir(user_folder)
        except OSError:
            pass

    # Hapus semua record file di DB
    UserFile.query.filter_by(user_id=user.id).delete()

    # Hapus user
    db.session.delete(user)
    db.session.commit()

    flash(f"User '{user.username}' dan semua file-nya berhasil dihapus.", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Buat admin default kalau belum ada
        admin_username = "admin"
        admin_password = "admin123"  # Ganti sebelum dipakai beneran

        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            admin_password_hash = bcrypt.hashpw(
                admin_password.encode("utf-8"),
                bcrypt.gensalt()
            ).decode("utf-8")

            admin_user = User(
                username=admin_username,
                password_hash=admin_password_hash,
                is_admin=True,
            )
            db.session.add(admin_user)
            db.session.commit()
            print("=== Admin default dibuat ===")
            print(f"Username: {admin_username}")
            print(f"Password: {admin_password}")

    app.run(debug=True)