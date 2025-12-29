# Mini Secure Web Application – Flask Application

## 👨‍💻 Anggota Kelompok:

- **Jefry Antoni - 23524020**
- **Alit Kesatria Mendala - 23524027**
- **Hamas Fakhrurrozi - 23524032**

Mini Secure Web merupakan aplikasi web sederhana berbasis Python Flask yang dikembangkan sebagai bagian dari tugas mata kuliah Data & Software Security (IF5161).
Aplikasi ini bertujuan untuk mendemonstrasikan penerapan konsep dasar keamanan web, khususnya pada proses autentikasi pengguna, pengelolaan file, serta kontrol akses berbasis peran (role-based access control).

Fokus utama dari proyek ini adalah bagaimana praktik keamanan yang direkomendasikan (best practices) dapat diterapkan secara nyata pada aplikasi web skala kecil.

---

## ⭐ Fitur Utama Aplikasi

### 🔐 1. Manajemen Pengguna

Aplikasi menyediakan fitur registrasi dan login dengan mekanisme keamanan yang dirancang untuk mencegah penyalahgunaan akun.

- Registrasi pengguna dilengkapi dengan validasi username dan password:
  - Username terdiri dari 3–20 karakter, hanya mengandung huruf, angka, dan underscore, serta diawali huruf.
  - Password minimal 8 karakter dan wajib mengandung huruf besar, huruf kecil, angka, serta karakter spesial.
- Proses login dilengkapi CAPTCHA dan mekanisme pembatasan percobaan login (*rate limiting*).
- Password tidak pernah disimpan dalam bentuk *plaintext*, melainkan di-hash menggunakan **bcrypt**.
- Apabila pengguna gagal login sebanyak tiga kali berturut-turut, sistem akan menerapkan *cooldown* secara bertahap (5, 10, hingga 20 menit).
- Sistem (*session*) dilengkapi *auto-logout* apabila tidak ada aktivitas selama 5 menit.
- Cookie sesi dikonfigurasi menggunakan atribut keamanan **HttpOnly**, **Secure (HTTPS)**, dan **SameSite=Lax**.
---

### 📤 2. Data Submission & Upload File (Secure Upload)
Pengguna dapat mengunggah file disertai deskripsi atau komentar.
- Nama file disanitasi menggunakan `secure_filename`.
- Sistem hanya mengizinkan tipe file tertentu melalui mekanisme *whitelist* (`txt, pdf, png, jpg, jpeg, gif`).
- Ukuran file dibatasi maksimal **5MB**.
- File disimpan dalam folder terpisah untuk setiap pengguna (`uploads/<user_id>/`) guna mencegah akses tidak sah antar pengguna.
- Mekanisme otorisasi diterapkan untuk memastikan pengguna hanya dapat mengakses file miliknya sendiri.

---

### 📥 3. Download File
- User hanya bisa mengunduh file miliknya
- Admin dapat mengunduh semua file
- **Authorization check** untuk mencegah unauthorized access

---

### 🗑️ 4. Delete File
- User dapat menghapus file miliknya
- Admin dapat menghapus file siapa pun
- Konfirmasi delete menggunakan **SweetAlert2**

---

### 🛡️ 5. Admin Panel
Admin dapat:
- Melihat seluruh user
- Menghapus user (beserta semua file miliknya)
- Melihat seluruh file dari semua user
- Menghapus file dari user mana pun
- Melihat statistik total user & total file
- Akses eksklusif: menu admin hanya muncul untuk akun admin

**Akun Admin** dibuat otomatis dari environment variable:
```bash
# Default (untuk development)
Username: admin
Password: admin123

# Production (set via environment variable)
export ADMIN_USERNAME=your_admin_name
export ADMIN_PASSWORD=your_strong_password
```

⚠️ **WARNING**: Aplikasi akan menampilkan peringatan jika menggunakan password default di production!

---

## 🔒 Fitur Security

### ✅ Implementasi OWASP Best Practices

| Security Feature | Status | Implementation |
|-----------------|--------|----------------|
| **Password Hashing** | ✅ | bcrypt dengan salt |
| **CSRF Protection** | ✅ | Flask-WTF CSRF tokens di semua form |
| **Input Validation** | ✅ | Regex validation untuk username & password |
| **File Upload Sanitization** | ✅ | `secure_filename` + whitelist + size limit |
| **Access Control** | ✅ | Decorator `@login_required` & `@admin_required` |
| **Session Security** | ✅ | HttpOnly, Secure, SameSite cookies |
| **No Hardcoded Secrets** | ✅ | Environment variables untuk credentials |
| **No Plaintext Passwords** | ✅ | Semua password di-hash dengan bcrypt |
| **Rate Limiting** | ✅ | Login cooldown dengan exponential backoff |
| **Session Timeout** | ✅ | Auto-logout setelah 5 menit idle |

### 🔐 Security Features Detail:

1. **Strong Password Policy**
   - Minimal 8 karakter
   - Harus mengandung: huruf besar, huruf kecil, angka, karakter spesial

2. **Username Validation**
   - Minimal 3 karakter, maksimal 20 karakter
   - Hanya alphanumeric dan underscore
   - Harus dimulai dengan huruf

3. **CSRF Protection**
   - Semua form POST dilindungi dengan CSRF token
   - Flask-WTF otomatis validasi token

4. **Session Security**
   - `SESSION_COOKIE_SECURE`: Cookie hanya dikirim via HTTPS (production)
   - `SESSION_COOKIE_HTTPONLY`: Cookie tidak bisa diakses JavaScript (XSS protection)
   - `SESSION_COOKIE_SAMESITE`: Lax (CSRF additional layer)

5. **File Upload Security**
   - Extension whitelist
   - Filename sanitization
   - Size limit: 5MB maximum
   - Per-user folder isolation

6. **Authentication Security**
   - CAPTCHA pada login
   - Rate limiting dengan cooldown
   - Session timeout
   - bcrypt password hashing

---

## 🧰 Teknologi yang Digunakan

| Teknologi | Versi | Keterangan |
|----------|-------|------------|
| **Python** | 3.x | Programming language |
| **Flask** | 3.0.0 | Backend web framework |
| **Flask-SQLAlchemy** | 3.1.1 | ORM untuk SQLite |
| **Flask-WTF** | 1.2.1 | CSRF protection |
| **bcrypt** | 4.1.2 | Password hashing |
| **Werkzeug** | 3.0.1 | WSGI utilities & secure filename |
| **SQLite** | - | Database lokal |
| **Bootstrap 5** | - | UI styling |
| **Bootstrap Icons** | - | Icon tombol aksi |
| **DataTables.js** | - | Tabel dinamis (search, sort, pagination) |
| **SweetAlert2** | - | Pop-up modern (notifikasi & konfirmasi) |
| **Gunicorn** | 21.2.0 | WSGI HTTP Server (production) |

---

## 📂 Struktur Folder

```
mini-secure-web-if5161/
│
├── app.py                  # Main application file
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
├── README.MD              # This file
├── Procfile               # Deployment config (Heroku/Render)
├── render.yaml            # Render.com deployment config
│
├── templates/             # Jinja2 HTML templates
│   ├── base.html         # Base template with navbar
│   ├── login.html        # Login page with CAPTCHA
│   ├── register.html     # Registration with validation hints
│   ├── dashboard.html    # User dashboard
│   ├── upload.html       # File upload page
│   └── admin_dashboard.html  # Admin panel
│
├── uploads/              # User uploaded files (auto-created)
│   └── <user_id>/        # Per-user folders
│
├── app.db                # SQLite database (auto-created)
└── venv/                 # Virtual environment (not in Git)
```

---

## 🚀 Cara Menjalankan

### 1. Clone repository
```bash
git clone https://github.com/hamaazz/mini-secure-web-if5161.git
cd mini-secure-web-if5161
```

### 2. Buat virtual environment
```bash
python -m venv venv
```

**Aktifkan:**

**Windows:**
```bash
venv\Scripts\activate
```

**Mac/Linux:**
```bash
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set environment variables (opsional, untuk production)

**Windows PowerShell:**
```powershell
$env:FLASK_ENV="production"
$env:SECRET_KEY="your-very-secret-key-here"
$env:ADMIN_USERNAME="superadmin"
$env:ADMIN_PASSWORD="YourStr0ng@Password!"
```

**Linux/Mac:**
```bash
export FLASK_ENV=production
export SECRET_KEY=your-very-secret-key-here
export ADMIN_USERNAME=superadmin
export ADMIN_PASSWORD=YourStr0ng@Password!
```

**Untuk development (localhost HTTP):**
```bash
# Windows
$env:FLASK_ENV="development"

# Linux/Mac
export FLASK_ENV=development
```

### 5. Jalankan aplikasi
```bash
python app.py
```

Akses di browser: **http://127.0.0.1:5000**

---

## 🧪 Testing

### Test User Registration
1. Akses halaman Register
2. Coba username: `ab` → Harus error (minimal 3 karakter)
3. Coba password: `weak` → Harus error (tidak memenuhi policy)
4. Gunakan username valid & password kuat → Berhasil register

### Test Login Security
1. Login dengan password salah 3x → Akun ter-cooldown 5 menit
2. Login tanpa isi CAPTCHA → Harus error
3. Login dengan credentials benar → Berhasil masuk

### Test Session Timeout
1. Login berhasil
2. Diamkan browser selama 6 menit (jangan klik apa-apa)
3. Refresh page → Auto-logout dengan pesan "tidak aktif lebih dari 5 menit"

### Test File Upload
1. Upload file < 5MB → Berhasil
2. Upload file > 5MB → Error "File terlalu besar!"
3. Upload file dengan extension `.exe` → Error "Tipe file tidak diizinkan"

### Test Authorization
1. Login sebagai user A, upload file
2. Logout, login sebagai user B
3. Coba akses file user A via direct URL → Harus error 403 Forbidden

---

## 🔧 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `production` | `development` atau `production` |
| `SECRET_KEY` | (default) | Secret key untuk Flask session |
| `ADMIN_USERNAME` | `admin` | Username admin default |
| `ADMIN_PASSWORD` | `admin123` | Password admin default ⚠️ |
| `PORT` | `5000` | Port untuk menjalankan aplikasi |

⚠️ **PENTING untuk Production:**
- Selalu set `SECRET_KEY` dengan value yang random & kuat
- Selalu set `ADMIN_PASSWORD` dengan password yang kuat
- Set `FLASK_ENV=production` untuk enable HTTPS cookies

---

## 📚 Documentation

### Database Models

**User Model:**
- `id`: Primary key
- `username`: Unique, 3-20 karakter
- `password_hash`: bcrypt hashed password
- `is_admin`: Boolean flag
- `failed_login_attempts`: Counter untuk rate limiting
- `lock_until`: Timestamp untuk cooldown

**UserFile Model:**
- `id`: Primary key
- `user_id`: Foreign key ke User
- `original_filename`: Nama file asli
- `stored_filename`: UUID + nama file (di server)
- `mimetype`: MIME type file
- `uploaded_at`: Timestamp upload
- `description`: Deskripsi/komentar user

### API Endpoints

| Route | Method | Auth | Description |
|-------|--------|------|-------------|
| `/` | GET | - | Redirect ke login/dashboard |
| `/register` | GET, POST | - | Halaman registrasi |
| `/login` | GET, POST | - | Halaman login dengan CAPTCHA |
| `/logout` | GET | ✅ | Logout user |
| `/dashboard` | GET | ✅ User | Dashboard user |
| `/upload` | GET, POST | ✅ User | Upload file |
| `/download/<id>` | GET | ✅ | Download file (owner/admin) |
| `/delete/<id>` | POST | ✅ | Delete file (owner/admin) |
| `/admin` | GET | ✅ Admin | Admin dashboard |
| `/admin/users/<id>/delete` | POST | ✅ Admin | Delete user |

---

## 🔒 Security Notes

### ✅ Yang Sudah Diimplementasi:
- Password tidak pernah disimpan dalam plaintext
- File upload disimpan dengan nama aman (UUID + original name)
- Setiap user memiliki folder file sendiri → mencegah akses tidak sah
- Admin diperiksa melalui decorator `@admin_required`
- Semua aksi sensitif (delete user/file) memakai method POST + konfirmasi
- SweetAlert2 digunakan agar user tidak salah klik
- CSRF token di semua form POST
- Session cookie dengan security flags
- Input validation dengan regex
- Rate limiting pada login
- Session timeout otomatis
- File size limit enforcement

---

## 📄 License

Project ini dibuat untuk keperluan pembelajaran.

---

**⭐ Happy Coding & Stay Secure! 🔒**
