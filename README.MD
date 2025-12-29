# Mini Secure Web – Flask Application

## Anggota Kelompok
- **Jefry Antoni** - 23524020
- **Alit Kesatria Mendala** - 23524027
- **hamas fakhrurrozi** - 23524032

---

## Deskripsi Aplikasi

Mini Secure Web merupakan aplikasi web sederhana berbasis Python Flask yang dikembangkan sebagai bagian dari tugas mata kuliah Data & Software Security (IF5161).

Aplikasi ini bertujuan untuk mendemonstrasikan penerapan konsep dasar keamanan web, khususnya pada proses autentikasi pengguna, pengelolaan file, serta kontrol akses berbasis peran (role-based access control).

Fokus utama dari proyek ini adalah bagaimana praktik keamanan yang direkomendasikan (best practices) dapat diterapkan secara nyata pada aplikasi web skala kecil.

---

## Fitur Utama

### 1. User Management
- **Register & Login**
  - Username minimal 3 karakter, harus dimulai huruf, cuma boleh alphanumeric + underscore
  - Password minimal 8 karakter, wajib ada: huruf besar, huruf kecil, angka, karakter spesial
  - Password di-hash pakai bcrypt (gak disimpan plain text)
- **Session Management**
  - Auto-logout kalau gak ada aktivitas 5 menit
  - Cookie secure: HttpOnly, Secure (HTTPS), SameSite=Lax
  - Timezone WIB (UTC+7) untuk timestamp
- **Login Protection**
  - Ada CAPTCHA (math sederhana)
  - Rate limiting: salah 3x login → cooldown 5 menit, terus nambah eksponensial (5, 10, 20 menit)

### 2. Upload & Download File
- User bisa upload file dengan deskripsi/komentar
- Tipe file yang diizinkan: txt, pdf, png, jpg, jpeg, gif
- Maksimal ukuran: **5MB**
- Nama file di-sanitize pakai `secure_filename()`
- File disimpan per-user (di folder `uploads/<user_id>/`)
- User cuma bisa download file milik sendiri
- Admin bisa download semua file

### 3. Admin Panel
Admin punya akses khusus:
- Lihat semua user yang terdaftar
- Hapus user (termasuk semua filenya)
- Lihat & hapus file dari user mana pun
- Lihat statistik (total user & total file)

**Login Admin:**
- Default: `admin` / `admin123` (development)
- Production: set via environment variable `ADMIN_USERNAME` & `ADMIN_PASSWORD`
- Aplikasi kasih warning kalau masih pakai password default

---

## Aspek Security yang Diterapkan

Sesuai requirement assignment, aplikasi ini sudah implement:

**1. Password Hashing**
- Pakai bcrypt dengan salt
- Password gak pernah disimpan dalam bentuk plain text
- Implementasi: `bcrypt.hashpw()` saat register, `bcrypt.checkpw()` saat login

**2. CSRF Protection**
- Semua form POST pakai CSRF token (Flask-WTF)
- Token auto-validasi setiap submit
- Implementasi: `CSRFProtect(app)` di app.py

**3. Input Validation**
- Username & password divalidasi pakai regex
- Password policy ketat (length + complexity)
- File extension whitelist
- Implementasi: `validate_username()` dan `validate_password()` di app.py:124-172

**4. File Upload Sanitization**
- Nama file di-sanitize pakai `secure_filename()`
- Validasi extension (whitelist)
- Size limit 5MB (`MAX_CONTENT_LENGTH`)
- File disimpan di folder terpisah per-user
- Unique filename pakai UUID untuk avoid collision

**5. Access Control**
- Authorization check di setiap endpoint
- Decorator `@login_required` & `@admin_required`
- User A gak bisa akses file user B
- Implementasi: app.py:181-198 (decorators), cek ownership di download/delete

**6. Session Security**
- `SESSION_COOKIE_SECURE`: Cookie cuma dikirim via HTTPS (production)
- `SESSION_COOKIE_HTTPONLY`: JavaScript gak bisa akses cookie (anti XSS)
- `SESSION_COOKIE_SAMESITE`: Lax (extra protection dari CSRF)
- Auto-logout setelah idle 5 menit
- Implementasi: app.py:40-46 (config), app.py:55-87 (timeout check)

**7. No Hardcoded Secrets**
- Admin credentials dari environment variable
- SECRET_KEY dari env variable
- Warning kalau pakai default credentials
- Implementasi: app.py:32, app.py:561-570

**8. Rate Limiting**
- Login dibatasi: 3x salah → cooldown
- Cooldown makin lama (exponential backoff: 5, 10, 20 menit)
- Implementasi: app.py:276-328 (login route)

---

## Teknologi

- **Backend:** Flask 3.0.0, Flask-SQLAlchemy 3.1.1
- **Database:** SQLite (lokal)
- **Security:** bcrypt 4.1.2, Flask-WTF 1.2.1 (CSRF)
- **Frontend:** Bootstrap 5, DataTables.js, SweetAlert2
- **Deployment:** Gunicorn 21.2.0
- **Timezone:** WIB (UTC+7) via Python datetime

---

## Cara Menjalankan

### 1. Clone & Setup

```bash
git clone https://github.com/hamaazz/mini-secure-web-if5161.git
cd mini-secure-web-if5161
```

### 2. Virtual Environment

**Buat venv:**
```bash
python -m venv venv
```

**Aktifkan:**
- Windows: `venv\Scripts\activate`
- Mac/Linux: `source venv/bin/activate`

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Environment Variables (opsional)

**Development (localhost HTTP):**
```bash
# Windows
$env:FLASK_ENV="development"

# Mac/Linux
export FLASK_ENV=development
```

**Production (HTTPS):**
```bash
# Windows
$env:FLASK_ENV="production"
$env:SECRET_KEY="your-random-secret-key"
$env:ADMIN_PASSWORD="YourStr0ngP@ss!"

# Mac/Linux
export FLASK_ENV=production
export SECRET_KEY=your-random-secret-key
export ADMIN_PASSWORD=YourStr0ngP@ss!
```

> **Note:** Kalau gak set `FLASK_ENV=development`, cookie Secure bakal aktif dan butuh HTTPS. Di localhost HTTP bakalan gak bisa login.

### 5. Jalankan

```bash
python app.py
```

Buka browser: **http://127.0.0.1:5000**

---

## Testing

### Test Register
1. Coba username `ab` → error (minimal 3 karakter)
2. Coba username `123test` → error (harus dimulai huruf)
3. Coba password `weak` → error (gak memenuhi policy)
4. Pakai password kuat misal `Test123!@#` → berhasil

### Test Login Security
1. Login salah 3x → kena cooldown 5 menit
2. Captcha salah → gak bisa login
3. Login benar → masuk dashboard

### Test File Upload
1. Upload file < 5MB → berhasil
2. Upload file > 5MB → error "File terlalu besar!"
3. Upload file `.exe` → error "Tipe file tidak diizinkan"

### Test Authorization
1. Login user A, upload file
2. Logout, login user B
3. Coba akses file user A via URL → error 403 Forbidden

### Test Timezone
1. Upload file dan cek "Waktu Upload"
2. Harusnya muncul waktu WIB (UTC+7), bukan UTC

---

## Deployment ke Render.com

### Quick Deploy

1. Push code ke GitHub
2. Buat account di [render.com](https://render.com)
3. New → Web Service → Connect repository
4. Set environment variables:
   - `FLASK_ENV`: `production`
   - `SECRET_KEY`: (klik Generate)
   - `ADMIN_PASSWORD`: (set password kuat)
5. Deploy!

File `render.yaml` udah include config lengkap.

### Environment Variables di Render

| Variable | Value | Keterangan |
|----------|-------|------------|
| `PYTHON_VERSION` | `3.11.0` | Python version |
| `FLASK_ENV` | `production` | Wajib untuk HTTPS cookies |
| `SECRET_KEY` | (auto-generate) | Secret key Flask |
| `ADMIN_PASSWORD` | (strong password) | Jangan pakai default! |

---

## Struktur Folder

```
mini-secure-web-if5161/
├── app.py                    # Main application
├── requirements.txt          # Dependencies
├── render.yaml              # Deployment config
├── templates/               # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   └── admin_dashboard.html
└── uploads/                 # User files (auto-created)
    └── <user_id>/
```

---

## Database Schema

**User:**
- `id` (Primary Key)
- `username` (Unique, String)
- `password_hash` (String, bcrypt hash)
- `is_admin` (Boolean)
- `failed_login_attempts` (Integer, untuk rate limiting)
- `lock_until` (DateTime, untuk cooldown)

**UserFile:**
- `id` (Primary Key)
- `user_id` (Foreign Key → User)
- `original_filename` (String)
- `stored_filename` (String, UUID + original name)
- `mimetype` (String)
- `uploaded_at` (DateTime, WIB timezone)
- `description` (Text)

---

## Penjelasan Kode Penting

### Password Validation (app.py:145-172)
```python
def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password minimal 8 karakter."
    if not re.search(r"[A-Z]", password):
        return False, "Password harus mengandung minimal 1 huruf besar (A-Z)."
    # ... validasi lainnya
    return True, ""
```

### Session Timeout (app.py:55-87)
```python
@app.before_request
def check_idle_timeout():
    now = dt.datetime.now(WIB).replace(tzinfo=None)
    last_active_str = session.get("last_active")
    # ... cek idle duration
    if idle_duration > timedelta(minutes=IDLE_TIMEOUT_MINUTES):
        session.clear()
        flash("Anda sudah logout karena tidak aktif lebih dari 5 menit.", "info")
        return redirect(url_for("login"))
```

### File Upload Authorization (app.py:418-434)
```python
@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    user = get_current_user()
    user_file = UserFile.query.get_or_404(file_id)

    # pemilik boleh download, admin boleh download semua
    if (not user.is_admin) and (user_file.user_id != user.id):
        abort(403)

    # ... return file
```

### Rate Limiting Login (app.py:300-328)
```python
user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
if user.failed_login_attempts >= 3:
    # Exponential backoff: 5, 10, 20, 40 menit
    extra_index = user.failed_login_attempts - 3
    wait_minutes = 5 * (2 ** extra_index)
    user.lock_until = now + dt.timedelta(minutes=wait_minutes)
```

---

## Security Implementation Checklist

Aplikasi ini udah cover semua requirement security dari assignment:

- ✅ **Password hashing** pakai bcrypt (app.py:246-249, 290-293)
- ✅ **CSRF protection** di semua form POST (app.py:49)
- ✅ **Input validation** username & password dengan regex (app.py:124-172)
- ✅ **File upload sanitization** dengan `secure_filename()` dan whitelist (app.py:393)
- ✅ **Access control** dengan decorators & ownership check (app.py:181-198, 425-426)
- ✅ **Gak ada hardcoded secrets** - pakai environment variables (app.py:32, 561-562)
- ✅ **Password gak disimpan plain text** - selalu di-hash (app.py:246-249)
- ✅ **Session secure** - cookie flags HttpOnly, Secure, SameSite (app.py:40-46)

---

## Bonus Features

Beberapa fitur tambahan yang diimplementasi:

- **Strong password policy** dengan complexity requirement (min 8 char, huruf besar/kecil, angka, spesial)
- **Username validation** pakai regex (harus dimulai huruf, alphanumeric + underscore)
- **File size limit** 5MB (DoS prevention)
- **Login rate limiting** dengan exponential backoff (brute force prevention)
- **Session timeout** 5 menit idle (reduce hijacking risk)
- **CAPTCHA** math sederhana (anti bot)
- **Admin panel** untuk user management & file monitoring
- **Timezone WIB** untuk timestamp yang akurat (UTC+7)
- **Per-user file isolation** di folder terpisah
- **Unique filename** dengan UUID (collision prevention)

---

## Production Tips

Kalau mau deploy production:

- **Wajib** ganti password admin (jangan `admin123`)
- Set `SECRET_KEY` yang kuat & random (misal: `openssl rand -hex 32`)
- Set `FLASK_ENV=production` biar cookie Secure aktif
- Pakai HTTPS (Render free plan udah include SSL)
- Free tier Render sleep setelah 15 menit idle (cold start ~30 detik)
- Kalau butuh database persistent, pakai PostgreSQL (gratis di Render)

---

## Limitations

- **SQLite (file-based)** → data ilang kalau redeploy di Render free tier
  - Solusi: pakai Render PostgreSQL (gratis)
- **Free tier Render** ada cold start ~30 detik kalau idle
- **Admin tidak bisa upload file** (by design, admin cuma untuk monitoring)
- **CAPTCHA sederhana** (math) → bisa di-upgrade pakai reCAPTCHA

---

## Troubleshooting

**Q: Gak bisa login di localhost?**
A: Set `FLASK_ENV=development` karena cookie Secure butuh HTTPS

```bash
# Windows
$env:FLASK_ENV="development"

# Mac/Linux
export FLASK_ENV=development
```

**Q: Admin password gak work?**
A: Cek env variable `ADMIN_PASSWORD`. Kalau udah ada admin sebelumnya, hapus `app.db` dulu:

```bash
# Hapus database lama
rm app.db  # Mac/Linux
del app.db  # Windows

# Jalankan ulang
python app.py
```

**Q: File upload error?**
A: Cek size file (max 5MB) dan tipe file (cuma txt, pdf, png, jpg, jpeg, gif)

**Q: Deploy Render gagal?**
A: Cek logs di Render dashboard. Pastikan semua env variable udah di-set

**Q: Waktu upload gak sesuai?**
A: Aplikasi pakai timezone WIB (UTC+7). Kalau database dibuat sebelum implementasi timezone, hapus `app.db` dan recreate

**Q: Kena rate limiting terus?**
A: Tunggu cooldown selesai atau hapus `app.db` untuk reset counter (development only)

---

## Development Notes

### Jika Ingin Extend Aplikasi

**Tambah tipe file baru:**
```python
# app.py:29
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "docx", "xlsx"}
```

**Ubah session timeout:**
```python
# app.py:53
IDLE_TIMEOUT_MINUTES = 10  # ganti dari 5 ke 10 menit
```

**Ubah file size limit:**
```python
# app.py:38
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB
```

**Tambah field di UserFile:**
```python
# app.py - tambah column baru di class UserFile
file_size = db.Column(db.Integer)  # dalam bytes

# Jangan lupa hapus app.db dan recreate
```

---

## Testing Security

### Manual Security Testing

**1. Test SQL Injection:**
```
Username: admin' OR '1'='1
Password: anything
→ Seharusnya gagal (SQLAlchemy sudah handle parameterized query)
```

**2. Test XSS:**
```
Deskripsi file: <script>alert('XSS')</script>
→ Seharusnya di-escape oleh Jinja2 auto-escaping
```

**3. Test Path Traversal:**
```
Upload file dengan nama: ../../etc/passwd
→ Seharusnya di-sanitize oleh secure_filename()
```

**4. Test CSRF:**
```
Buat form POST dari domain lain tanpa CSRF token
→ Seharusnya ditolak (403 Forbidden)
```

**5. Test Authorization:**
```
Login user A, ambil file_id
Logout, login user B
Akses /download/<file_id_dari_user_A>
→ Seharusnya 403 Forbidden
```

---

## Referensi

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Flask-WTF CSRF Protection](https://flask-wtf.readthedocs.io/en/stable/csrf.html)
- [bcrypt Password Hashing](https://pypi.org/project/bcrypt/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Render Deployment Guide](https://render.com/docs)

---

## License

Project ini dibuat untuk keperluan pembelajaran web security & backend development sebagai tugas mata kuliah Data & Software Security (IF5161).

---

**Developed by:**
- Jefry Antoni - 23524020
- Alit Kesatria Mendala - 23524027
- hamas fakhrurrozi - 23524032

**Course:** IF5161 - Data & Software Security
**Institution:** Institut Teknologi Bandung
**Year:** 2024/2025
