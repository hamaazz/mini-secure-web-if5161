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
  - Password di-hash menggunakan bcrypt (tidak disimpan plain text)
- **Session Management**
  - Auto-logout jika tidak ada aktivitas 5 menit
  - Cookie secure: HttpOnly, Secure (HTTPS), SameSite=Lax
  - Timezone WIB (UTC+7) untuk timestamp
- **Login Protection**
  - CAPTCHA (math sederhana)
  - Rate limiting: salah 3x login → cooldown 5 menit, eksponensial (5, 10, 20 menit)

### 2. Upload & Download File
- User bisa upload file dengan deskripsi/komentar
- Tipe file yang diizinkan: txt, pdf, png, jpg, jpeg, gif
- Maksimal ukuran: **5MB**
- Nama file di-sanitize pakai `secure_filename()`
- File disimpan per-user (di folder `uploads/<user_id>/`)
- User hanya bisa download file milik sendiri
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
- Aplikasi memberikan warning jika masih pakai password default

---

## Aspek Security yang Diterapkan

**1. Password Hashing**
- Pakai bcrypt dengan salt
- Password tidak pernah disimpan dalam bentuk plain text
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
- User A tidak bisa akses file user B

**6. Session Security**
- `SESSION_COOKIE_SECURE`: Cookie cuma dikirim via HTTPS (production)
- `SESSION_COOKIE_HTTPONLY`: JavaScript gak bisa akses cookie (anti XSS)
- `SESSION_COOKIE_SAMESITE`: Lax (extra protection dari CSRF)
- Auto-logout setelah idle 5 menit

**7. No Hardcoded Secrets**
- Admin credentials dari environment variable
- SECRET_KEY dari env variable
- Warning jika menggunakan default credentials

**8. Rate Limiting**
- Login dibatasi: 3x salah → cooldown
- Cooldown makin lama (exponential backoff: 5, 10, 20 menit)

---

## Teknologi

- **Backend:** Flask 3.0.0, Flask-SQLAlchemy 3.1.1
- **Database:** SQLite (lokal)
- **Security:** bcrypt 4.1.2, Flask-WTF 1.2.1 (CSRF)
- **Frontend:** Bootstrap 5, DataTables.js, SweetAlert2
- **Deployment:** Gunicorn 21.2.0

---

## Cara Install

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
2. Coba username `123test` → error (harus dimulai dengan huruf)
3. Coba password `weak` → error (tidak memenuhi policy)
4. Pakai password kuat misal `Test123!@#` → berhasil

### Test Login Security
1. Login salah 3x → cooldown 5 menit
2. Captcha salah → tidak bisa login
3. Login benar → masuk dashboard

### Test File Upload
1. Upload file < 5MB → berhasil
2. Upload file > 5MB → error "File terlalu besar!"
3. Upload file `.exe` → error "Tipe file tidak diizinkan"

### Test Authorization
1. Login user A, upload file
2. Logout, login user B
3. Coba akses file user A via URL → error 403 Forbidden

---

## Struktur Folder

```
mini-secure-web-if5161/
├── app.py                    # Main application
├── requirements.txt          # Dependencies
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

## Security Implementation Checklist
- ✅ **Password hashing** menggunakan bcrypt (app.py:246-249, 290-293)
- ✅ **CSRF protection** di semua form POST (app.py:49)
- ✅ **Input validation** username & password dengan regex (app.py:124-172)
- ✅ **File upload sanitization** dengan `secure_filename()` dan whitelist (app.py:393)
- ✅ **Access control** dengan decorators & ownership check (app.py:181-198, 425-426)
- ✅ **Tidak ada hardcoded secrets** - pakai environment variables (app.py:32, 561-562)
- ✅ **Password tidak disimpan pada plain text** - selalu di-hash (app.py:246-249)
- ✅ **Session secure** - cookie flags HttpOnly, Secure, SameSite (app.py:40-46)

---

## Beberapa fitur lain yang diimplementasi:
- **Strong password policy** dengan complexity requirement (min 8 char, huruf besar/kecil, angka, spesial)
- **Username validation** pakai regex (harus dimulai huruf, alphanumeric + underscore)
- **File size limit** 5MB (DoS prevention)
- **Login rate limiting** dengan exponential backoff (brute force prevention)
- **Session timeout** 5 menit idle (reduce hijacking risk)
- **CAPTCHA** perhitungan matematika sederhana
- **Admin panel** untuk user management & file monitoring
- **Per-user file isolation** di folder terpisah
- **Unique filename** dengan UUID (collision prevention)

---

## Limitations

- **SQLite (file-based)**
- **Admin tidak dapat melakukan upload file**
- **CAPTCHA sederhana** (math)

---

## Troubleshooting

**Q: Tidak dapat login di localhost?**
A: Set `FLASK_ENV=development` karena cookie Secure butuh HTTPS

```bash
# Windows
$env:FLASK_ENV="development"

# Mac/Linux
export FLASK_ENV=development
```

**Q: Admin password not work?**
A: Cek env variable `ADMIN_PASSWORD`. Kalau sudah ada admin sebelumnya, hapus `app.db` dulu:

```bash
# Hapus database lama
rm app.db  # Mac/Linux
del app.db  # Windows

# Jalankan ulang
python app.py
```

**Q: File upload error?**
A: Cek size file (max 5MB) dan tipe file (cuma txt, pdf, png, jpg, jpeg, gif)

**Q: Terkena ratelimiting?**
A: Tunggu cooldown selesai atau hapus `app.db` untuk reset counter (development only)

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
→ Seharusnya dapat di-sanitize oleh secure_filename()
```

**4. Test CSRF:**
```
Buat form POST dari domain lain tanpa CSRF token
→ Output yang diharapkan 403 Forbidden
```

**5. Test Authorization:**
```
Login user A, ambil file_id
Logout, login user B
Akses /download/<file_id_dari_user_A>
→ Output yang diharapkan 403 Forbidden
```

---

## Referensi

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Flask-WTF CSRF Protection](https://flask-wtf.readthedocs.io/en/stable/csrf.html)
- [bcrypt Password Hashing](https://pypi.org/project/bcrypt/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## License

Project ini dibuat untuk keperluan pembelajaran serta sebagai tugas mata kuliah Data & Software Security (IF5161).

---

**Developed by:**
- Jefry Antoni - 23524020
- Alit Kesatria Mendala - 23524027
- Hamas Fakhrurrozi - 23524032

**Course:** IF5161 - Data & Software Security
**Institution:** Institut Teknologi Bandung
**Year:** 2025
