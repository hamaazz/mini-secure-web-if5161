# Mini Secure Web – Flask Application

A mini web application built using **Python Flask**, designed to demonstrate essential security features for user management, file handling, and administrative control.  
Project ini dibuat sebagai tugas mata kuliah/pembelajaran terkait web security & backend development.

---

## ⭐ Fitur Utama

### 🔐 1. User Management
- Register user dengan password **di-hash** menggunakan Werkzeug
- Login & logout menggunakan **Flask session**
- Validasi input user
- Halaman dashboard personal

---

### 📤 2. Upload File (Secure Upload)
- Sanitasi nama file menggunakan `secure_filename`
- Validasi ekstensi file (whitelist)
- Penyimpanan file per-user: `uploads/<user_id>/`
- Mencegah akses silang (user A tidak bisa mengakses file user B)

---

### 📥 3. Download File
- User hanya bisa mengunduh file miliknya
- Admin dapat mengunduh semua file

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

Akun Admin default dibuat otomatis:

username: admin
password: admin123

> bisa mengganti password di file `app.py`.

---

## 🧰 Teknologi yang Digunakan

| Teknologi | Keterangan |
|----------|------------|
| **Python Flask** | Backend server |
| **Flask SQLAlchemy** | ORM untuk SQLite |
| **Werkzeug** | Hashing password |
| **Bootstrap 5** | UI styling |
| **Bootstrap Icons** | Icon tombol aksi |
| **DataTables.js** | Tabel dinamis (search, sort, pagination) |
| **SweetAlert2** | Pop-up modern (notifikasi & konfirmasi) |
| **SQLite** | Database lokal |

---

## 📂 Struktur Folder
miniweb_security/
│ app.py
│ requirements.txt
│ .gitignore
│ README.md
│
├── templates/
│ ├── base.html
│ ├── login.html
│ ├── register.html
│ ├── dashboard.html
│ ├── upload.html
│ └── admin_dashboard.html
│
├── uploads/ ← otomatis dibuat, berisi file per-user
└── venv/ ← environment lokal (tidak ikut Git)

---

## 🚀 Cara Menjalankan

### 1. Clone repository
```bash
git clone https://github.com/hamaazz/mini-secure-web-if5161.git
cd mini-secure-web-if5161

2. Buat virtual environment
python -m venv venv

Aktifkan:
Windows:
venv\Scripts\activate

Mac/Linux:
source venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

4. Jalankan aplikasi
python app.py


Akses di browser: http://127.0.0.1:5000

🖼️ Screenshot (Optional)

Tambahkan screenshot aplikasi kamu di bagian ini:
![Login Page](screenshots/login.png)
![Dashboard](screenshots/dashboard.png)
![Admin Panel](screenshots/admin.png)

🔒 Catatan Security

-Password tidak pernah disimpan dalam plaintext.
-File upload disimpan dengan nama aman (uuid_originalname).
-Setiap user memiliki folder file sendiri → mencegah akses tidak sah.
-Admin diperiksa melalui decorator @admin_required.
-Semua aksi sensitif (delete user/file) memakai method POST + konfirmasi.
-SweetAlert2 digunakan agar user tidak salah klik.