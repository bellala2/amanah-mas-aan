# Amanah Auth API (Golang + PostgreSQL)

REST API untuk screen flow **Login Email**, **Login WhatsApp + OTP**, **Register**, dan **Lupa Password + OTP**.

**Stack:** Go 1.22 (`net/http`), PostgreSQL 13+ (`database/sql` + pgx), bcrypt, JWT HS256.

## Fitur
| Kebutuhan | Implementasi |
|---|---|
| Validasi input | Per field, response `422` dengan `details` per field (`internal/validator`) |
| Password hashing | bcrypt (cost 12). Aturan: ≥8 karakter, huruf besar+kecil, angka, simbol (sesuai UI) |
| Authentication | JWT access token 15 mnt + refresh token opaque (rotasi, deteksi reuse), `Authorization: Bearer` |
| OTP expiration & validation | 6 digit (`crypto/rand`), berlaku 5 mnt, maks 5 salah, sekali pakai, cooldown kirim-ulang 60 dtk, maks 5 OTP/jam, disimpan sebagai HMAC |
| Error handling | Envelope error seragam + kode error mesin-baca (`OTP_EXPIRED`, `ACCOUNT_LOCKED`, …) |
| HTTP status | 200/201, 400, 401, 403, 409, 410, 422, 423, 429, 500, 502 |
| Keamanan tambahan | Lockout akun (5 gagal → 15 mnt) + "sisa percobaan", anti user-enumeration (OTP request & forgot selalu 200), timing-equalization saat login, reset_token sekali pakai, semua sesi dicabut setelah reset password |
| Testing | Integration test lengkap di `internal/handler` (memakai repo in-memory, tanpa DB) + unit test validator |

## Struktur
```
cmd/server/main.go            entrypoint + graceful shutdown
internal/config               env config
internal/apperr               error terstruktur -> HTTP
internal/validator            validasi email, nomor HP (E.164), password
internal/model                entity
internal/repository           Store interface, Postgres, Memory (untuk test)
internal/service              logika bisnis (auth, otp, token, notifier)
internal/handler              HTTP handler, middleware, test
migrations/001_init.sql       skema DB
docs/DATABASE.md, erd.dbml    dokumen database + ERD
docs/openapi.yaml             Swagger/OpenAPI 3
postman/                      Postman collection
```

## Menjalankan
Prasyarat: Go 1.22+ dan PostgreSQL 13+ yang sudah terpasang.
```bash
# 1. Buat database & user (sekali saja)
psql -U postgres -c "CREATE USER amanah WITH PASSWORD 'amanah';"
psql -U postgres -c "CREATE DATABASE amanah OWNER amanah;"

# 2. Konfigurasi
cp .env.example .env        # sesuaikan DATABASE_URL, JWT_SECRET, OTP_SECRET
go mod tidy                 # sekali, untuk membuat go.sum

# 3. Migrasi & jalankan
make migrate                # menjalankan migrations/001_init.sql
make run                    # http://localhost:8080
make test                   # go test ./... -race (tidak butuh database)
```

> Dengan `DEBUG_OTP=true` (hanya development), kode OTP ikut muncul di response (`data.debug_otp`) dan log server, jadi flow bisa dites tanpa provider WhatsApp/email. Server menolak start jika `DEBUG_OTP=true` di `APP_ENV=production`.

## Dokumentasi API
- **Swagger:** buka <https://editor.swagger.io> lalu import `docs/openapi.yaml`.
- **Postman:** import `postman/amanah-auth.postman_collection.json`, jalankan folder berurutan (token & OTP tersimpan otomatis).

### Endpoint
| Flow | Method & Path | Auth |
|---|---|---|
| Register | `POST /api/v1/auth/register` | – |
| Login Email | `POST /api/v1/auth/login` | – |
| Login WA | `POST /api/v1/auth/login/whatsapp/request-otp` | – |
| | `POST /api/v1/auth/login/whatsapp/verify-otp` | – |
| Lupa Password | `POST /api/v1/auth/password/forgot` (`method`: email/whatsapp) | – |
| | `POST /api/v1/auth/password/verify-otp` → `reset_token` | – |
| | `POST /api/v1/auth/password/reset` → langsung login | reset_token |
| Session | `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout` | – |
| Profil | `GET /api/v1/me` | Bearer |

### Contoh
```bash
curl -X POST localhost:8080/api/v1/auth/register -H 'Content-Type: application/json' -d '{
  "full_name":"Budi Santoso","email":"budi.santoso@gmail.com","phone":"812-3456-7890",
  "password":"Rahasia@123","confirm_password":"Rahasia@123","accept_terms":true}'
```
```json
{ "success": true, "message": "Registrasi berhasil",
  "data": { "access_token": "eyJ...", "refresh_token": "…", "token_type": "Bearer", "expires_in": 900,
            "user": { "id": "…", "full_name": "Budi Santoso", "email": "budi.santoso@gmail.com",
                      "phone": "+6281234567890", "email_verified": false, "phone_verified": false } } }
```
Login gagal (UI "Autentikasi Gagal … Sisa 2x"):
```json
{ "success": false, "error": { "code": "INVALID_CREDENTIALS", "message": "Email/username atau kata sandi salah",
  "details": { "attempts_remaining": 2, "max_attempts": 5 } } }
```

### Kode error
| HTTP | code | Kapan |
|---|---|---|
| 400 | `INVALID_JSON`, `OTP_INVALID` | Body rusak / kode OTP salah (`details.attempts_remaining`) |
| 401 | `INVALID_CREDENTIALS`, `UNAUTHENTICATED`, `INVALID_TOKEN`, `TOKEN_EXPIRED` | Auth gagal |
| 403 | `ACCOUNT_DISABLED` | Akun suspended |
| 409 | `ALREADY_REGISTERED` | Email/nomor sudah terdaftar (`details` per field) |
| 410 | `OTP_EXPIRED` | OTP kedaluwarsa |
| 413 | `PAYLOAD_TOO_LARGE` | Body > 1 MB |
| 422 | `VALIDATION_ERROR` | Validasi field |
| 423 | `ACCOUNT_LOCKED` | Terlalu banyak login gagal (`Retry-After`) |
| 429 | `OTP_RESEND_COOLDOWN`, `OTP_RATE_LIMITED`, `OTP_MAX_ATTEMPTS` | Pembatasan OTP |
| 500 / 502 | `INTERNAL_ERROR`, `OTP_DELIVERY_FAILED` | Server / gagal kirim OTP |

## Alur Lupa Password
1. `POST /password/forgot` `{method, destination}` → OTP dikirim (selalu 200).
2. `POST /password/verify-otp` `{method, destination, otp}` → `reset_token` (JWT 10 mnt, terikat ke OTP tsb).
3. `POST /password/reset` `{reset_token, new_password, confirm_password}` → password diganti, OTP di-consume (token tidak bisa dipakai lagi), semua refresh token lama dicabut, user langsung login.

## Catatan produksi / pengembangan lanjutan
- Ganti `service.LogNotifier` dengan implementasi `Notifier` untuk provider WhatsApp (Fonnte/Twilio/WABA) dan SMTP/SES.
- Tambahkan rate limit per-IP di gateway/reverse proxy; jika di belakang proxy, ambil IP dari `X-Forwarded-For` (lihat `clientMeta`).
- Jadwalkan cleanup OTP & refresh token kedaluwarsa (SQL ada di `docs/DATABASE.md`).
- Simpan `JWT_SECRET`/`OTP_SECRET` di secret manager; jalankan di belakang HTTPS.
