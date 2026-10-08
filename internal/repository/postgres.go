package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"amanah-auth/internal/model"
)

type Postgres struct{ db *sql.DB }

func NewPostgres(db *sql.DB) *Postgres { return &Postgres{db: db} }

const userCols = `id, full_name, COALESCE(username,''), email, phone, password_hash,
	email_verified_at, phone_verified_at, status, failed_login_attempts, locked_until, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func nt(n sql.NullTime) *time.Time {
	if n.Valid {
		t := n.Time
		return &t
	}
	return nil
}

func scanUser(r scanner) (*model.User, error) {
	var u model.User
	var ev, pv, lu sql.NullTime
	err := r.Scan(&u.ID, &u.FullName, &u.Username, &u.Email, &u.Phone, &u.PasswordHash,
		&ev, &pv, &u.Status, &u.FailedLoginAttempts, &lu, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.EmailVerifiedAt, u.PhoneVerifiedAt, u.LockedUntil = nt(ev), nt(pv), nt(lu)
	return &u, nil
}

func (p *Postgres) getUser(ctx context.Context, where string, arg any) (*model.User, error) {
	return scanUser(p.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE `+where, arg))
}

func (p *Postgres) CreateUser(ctx context.Context, u *model.User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	now := time.Now()
	u.Status = "active"
	u.CreatedAt = now
	u.UpdatedAt = now

	usernameVal := u.Username
    if usernameVal == "" {
        usernameVal = "" 
    }

	_, err := p.db.ExecContext(ctx,
        `INSERT INTO users (id, full_name, username, email, phone, password_hash, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        u.ID, u.FullName, usernameVal, u.Email, u.Phone, u.PasswordHash, u.Status, u.CreatedAt, u.UpdatedAt,
    )

	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) && myErr.Number == 1062 { // 1062 = Duplicate entry (MySQL)
		return ErrEmailTaken // Atau ditangani fleksibel di level service
	}
	return err
}

func (p *Postgres) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	return p.getUser(ctx, `id = ?`, id)
}

func (p *Postgres) GetUserByIdentifier(ctx context.Context, ident string) (*model.User, error) {
	return scanUser(p.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ? OR username = ?`, ident, ident))
}

func (p *Postgres) GetUserByEmail(ctx context.Context, e string) (*model.User, error) {
	return p.getUser(ctx, `email = ?`, e)
}

func (p *Postgres) GetUserByPhone(ctx context.Context, ph string) (*model.User, error) {
	return p.getUser(ctx, `phone = ?`, ph)
}

func (p *Postgres) UpdatePassword(ctx context.Context, userID, hash string) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE users SET password_hash=?, failed_login_attempts=0, locked_until=NULL, updated_at=NOW() WHERE id=?`,
		hash, userID)
	return err
}

func (p *Postgres) RegisterFailedLogin(ctx context.Context, userID string, max int, lockFor time.Duration, now time.Time) (int, *time.Time, error) {
	var attempts int

	// Ambil angka attempts sekarang dari database
	err := p.db.QueryRowContext(ctx, `SELECT failed_login_attempts FROM users WHERE id = ?`, userID).Scan(&attempts)
	if err != nil {
		return 0, nil, err
	}

	attempts++
	var lockUntil *time.Time
	if attempts >= max {
		t := now.Add(lockFor)
		lockUntil = &t
	}

	_, err = p.db.ExecContext(ctx,
		`UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = NOW() WHERE id = ?`,
		attempts, lockUntil, userID)

	return attempts, lockUntil, err
}

func (p *Postgres) ResetFailedLogin(ctx context.Context, userID string) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE users SET failed_login_attempts=0, locked_until=NULL, updated_at=NOW() WHERE id=?`, userID)
	return err
}

func (p *Postgres) MarkPhoneVerified(ctx context.Context, userID string, at time.Time) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE users SET phone_verified_at=COALESCE(phone_verified_at,?), updated_at=NOW() WHERE id=?`, at, userID)
	return err
}

// ---------- OTP ----------

func (p *Postgres) CreateOTP(ctx context.Context, o *model.OTP) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err = tx.ExecContext(ctx,
		`UPDATE otp_codes SET consumed_at=? WHERE destination=? AND purpose=? AND consumed_at IS NULL`,
		o.CreatedAt, o.Destination, o.Purpose); err != nil {
		return err
	}

	if o.ID == "" {
		o.ID = uuid.NewString()
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO otp_codes (id, user_id, channel, destination, purpose, code_hash, max_attempts, expires_at, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		o.ID, o.UserID, o.Channel, o.Destination, o.Purpose, o.CodeHash, o.MaxAttempts, o.ExpiresAt, o.CreatedAt,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) GetLatestOTP(ctx context.Context, dest, purpose string) (*model.OTP, error) {
	var o model.OTP
	var uid sql.NullString
	var vt, ct sql.NullTime
	err := p.db.QueryRowContext(ctx,
		`SELECT id, user_id, channel, destination, purpose, code_hash, attempts, max_attempts,
				expires_at, verified_at, consumed_at, created_at
		   FROM otp_codes WHERE destination=? AND purpose=? ORDER BY created_at DESC LIMIT 1`,
		dest, purpose).Scan(&o.ID, &uid, &o.Channel, &o.Destination, &o.Purpose, &o.CodeHash,
		&o.Attempts, &o.MaxAttempts, &o.ExpiresAt, &vt, &ct, &o.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if uid.Valid {
		s := uid.String
		o.UserID = &s
	}
	o.VerifiedAt, o.ConsumedAt = nt(vt), nt(ct)
	return &o, nil
}

func (p *Postgres) CountOTPsSince(ctx context.Context, dest, purpose string, since time.Time) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx,
		`SELECT count(*) FROM otp_codes WHERE destination=? AND purpose=? AND created_at >= ?`,
		dest, purpose, since).Scan(&n)
	return n, err
}

func (p *Postgres) IncrementOTPAttempts(ctx context.Context, id string) (int, error) {
	_, err := p.db.ExecContext(ctx, `UPDATE otp_codes SET attempts = attempts + 1 WHERE id=?`, id)
	if err != nil {
		return 0, err
	}

	var attempts int
	err = p.db.QueryRowContext(ctx, `SELECT attempts FROM otp_codes WHERE id=?`, id).Scan(&attempts)
	return attempts, err
}

func (p *Postgres) MarkOTPVerified(ctx context.Context, id string, at time.Time) error {
	_, err := p.db.ExecContext(ctx, `UPDATE otp_codes SET verified_at=? WHERE id=?`, at, id)
	return err
}

func (p *Postgres) ConsumeOTP(ctx context.Context, id string, at time.Time) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE otp_codes SET consumed_at=? WHERE id=? AND verified_at IS NOT NULL AND consumed_at IS NULL`, at, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- Refresh tokens ----------

func (p *Postgres) SaveRefreshToken(ctx context.Context, t *model.RefreshToken) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}

	_, err := p.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, user_agent, ip_address, created_at)
		 VALUES (?,?,?,?,?,?,?)`,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, trunc(t.UserAgent, 255), trunc(t.IP, 45), t.CreatedAt)
	return err
}

func (p *Postgres) GetRefreshToken(ctx context.Context, hash string) (*model.RefreshToken, error) {
	var t model.RefreshToken
	var rv sql.NullTime
	err := p.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, revoked_at, user_agent, ip_address, created_at
		   FROM refresh_tokens WHERE token_hash=?`, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &rv, &t.UserAgent, &t.IP, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.RevokedAt = nt(rv)
	return &t, nil
}

func (p *Postgres) RevokeRefreshToken(ctx context.Context, hash string, at time.Time) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL`, at, hash)
	return err
}

func (p *Postgres) RevokeAllRefreshTokens(ctx context.Context, userID string, at time.Time) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, at, userID)
	return err
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
