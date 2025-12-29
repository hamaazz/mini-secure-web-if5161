# Mini Secure Web – Flask Application

Aplikasi web sederhana yang dibuat dengan Flask untuk tugas IF5161 (Web Security).
Fokus utama: implementasi fitur security dasar yang wajib ada di web application.

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
- **Login Protection**
  - Ada CAPTCHA (math sederhana)
  - Rate limiting: salah 3x login → cooldown 5 menit, terus nambah eksponensial

### 2. Upload & Download File
- User bisa upload file dengan deskripsi/komentar
- Tipe file yang diizinkan: txt, pdf, png, jpg, jpeg, gif
- Maksimal ukuran: **5MB**
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

**2. CSRF Protection**
- Semua form POST pakai CSRF token (Flask-WTF)
- Token auto-validasi setiap submit

**3. Input Validation**
- Username & password divalidasi pakai regex
- Password policy ketat (length + complexity)
- File extension whitelist

**4. File Upload Sanitization**
- Nama file di-sanitize pakai `secure_filename()`
- Validasi extension (whitelist)
- Size limit 5MB
- File disimpan di folder terpisah per-user

**5. Access Control**
- Authorization check di setiap endpoint
- Decorator `@login_required` & `@admin_required`
- User A gak bisa akses file user B

**6. Session Security**
- `SESSION_COOKIE_SECURE`: Cookie cuma dikirim via HTTPS (production)
- `SESSION_COOKIE_HTTPONLY`: JavaScript gak bisa akses cookie (anti XSS)
- `SESSION_COOKIE_SAMESITE`: Lax (extra protection dari CSRF)

**7. No Hardcoded Secrets**
- Admin credentials dari environment variable
- SECRET_KEY dari env variable
- Warning kalau pakai default credentials

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
2. Coba password `weak` → error (gak memenuhi policy)
3. Pakai password kuat misal `Test123!@#` → berhasil

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
- id, username (unique), password_hash, is_admin
- failed_login_attempts, lock_until (untuk rate limiting)

**UserFile:**
- id, user_id (FK), original_filename, stored_filename
- mimetype, uploaded_at, description

---

## Notes

### Security Implementation
Aplikasi ini udah cover semua requirement security dari assignment:
- ✅ Password hashing pakai bcrypt
- ✅ CSRF protection di semua form
- ✅ Input validation (username & password)
- ✅ File upload sanitization
- ✅ Access control (authorization check)
- ✅ Gak ada hardcoded secrets
- ✅ Password gak disimpan plain text
- ✅ Session secure (cookie flags)

### Bonus Features
Beberapa fitur tambahan yang diimplementasi:
- Strong password policy dengan complexity requirement
- Username validation (regex)
- File size limit (DoS prevention)
- Login rate limiting (brute force prevention)
- Session timeout (reduce hijacking risk)
- CAPTCHA (anti bot)
- Admin panel (user management)

### Production Tips
Kalau mau deploy production:
- Wajib ganti password admin (jangan `admin123`)
- Set `SECRET_KEY` yang kuat & random
- Set `FLASK_ENV=production` biar cookie Secure aktif
- Pakai HTTPS (Render free plan udah include SSL)
- Free tier Render sleep setelah 15 menit idle

### Limitations
- SQLite (file-based) → data ilang kalau redeploy di Render
- Untuk production serius, pakai PostgreSQL
- Free tier Render ada cold start ~30 detik kalau idle

---

## Troubleshooting

**Q: Gak bisa login di localhost?**
A: Set `FLASK_ENV=development` karena cookie Secure butuh HTTPS

**Q: Admin password gak work?**
A: Cek env variable `ADMIN_PASSWORD`. Kalau udah ada admin sebelumnya, hapus `app.db` dulu

**Q: File upload error?**
A: Cek size file (max 5MB) dan tipe file (cuma txt, pdf, png, jpg, jpeg, gif)

**Q: Deploy Render gagal?**
A: Cek logs di Render dashboard. Pastikan semua env variable udah di-set

---

## Author

Hamzah - IF5161 Web Security

---

Project ini dibuat untuk keperluan pembelajaran web security & backend development.
