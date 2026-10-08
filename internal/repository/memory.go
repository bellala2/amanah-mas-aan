package repository

import (
	"context"
	"fmt"
	"sync"
	"time"

	"amanah-auth/internal/model"
)

// Memory adalah Store in-memory untuk unit/integration test (tanpa database).
type Memory struct {
	mu      sync.Mutex
	seq     int
	users   map[string]*model.User
	otps    []*model.OTP
	refresh map[string]*model.RefreshToken
}

func NewMemory() *Memory {
	return &Memory{users: map[string]*model.User{}, refresh: map[string]*model.RefreshToken{}}
}

func (m *Memory) id() string { m.seq++; return fmt.Sprintf("id-%d", m.seq) }

func cp[T any](v *T) *T { c := *v; return &c }

func (m *Memory) findUser(f func(*model.User) bool) (*model.User, error) {
	for _, u := range m.users {
		if f(u) {
			return cp(u), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) CreateUser(_ context.Context, u *model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.users {
		switch {
		case x.Email == u.Email:
			return ErrEmailTaken
		case x.Phone == u.Phone:
			return ErrPhoneTaken
		case u.Username != "" && x.Username == u.Username:
			return ErrUsernameTaken
		}
	}
	u.ID, u.Status = m.id(), "active"
	u.CreatedAt, u.UpdatedAt = time.Now(), time.Now()
	m.users[u.ID] = cp(u)
	return nil
}

func (m *Memory) GetUserByID(_ context.Context, id string) (*model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.findUser(func(u *model.User) bool { return u.ID == id })
}
func (m *Memory) GetUserByIdentifier(_ context.Context, s string) (*model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.findUser(func(u *model.User) bool { return u.Email == s || (u.Username != "" && u.Username == s) })
}
func (m *Memory) GetUserByEmail(_ context.Context, s string) (*model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.findUser(func(u *model.User) bool { return u.Email == s })
}
func (m *Memory) GetUserByPhone(_ context.Context, s string) (*model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.findUser(func(u *model.User) bool { return u.Phone == s })
}

func (m *Memory) UpdatePassword(_ context.Context, userID, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	u.PasswordHash, u.FailedLoginAttempts, u.LockedUntil = hash, 0, nil
	return nil
}

func (m *Memory) RegisterFailedLogin(_ context.Context, userID string, max int, lockFor time.Duration, now time.Time) (int, *time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return 0, nil, ErrNotFound
	}
	u.FailedLoginAttempts++
	if u.FailedLoginAttempts >= max {
		t := now.Add(lockFor)
		u.LockedUntil = &t
	}
	if u.LockedUntil != nil {
		t := *u.LockedUntil
		return u.FailedLoginAttempts, &t, nil
	}
	return u.FailedLoginAttempts, nil, nil
}

func (m *Memory) ResetFailedLogin(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[userID]; ok {
		u.FailedLoginAttempts, u.LockedUntil = 0, nil
	}
	return nil
}

func (m *Memory) MarkPhoneVerified(_ context.Context, userID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[userID]; ok && u.PhoneVerifiedAt == nil {
		u.PhoneVerifiedAt = &at
	}
	return nil
}

// ---------- OTP ----------

func (m *Memory) CreateOTP(_ context.Context, o *model.OTP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.otps {
		if x.Destination == o.Destination && x.Purpose == o.Purpose && x.ConsumedAt == nil {
			t := o.CreatedAt
			x.ConsumedAt = &t
		}
	}
	o.ID = m.id()
	m.otps = append(m.otps, cp(o))
	return nil
}

func (m *Memory) GetLatestOTP(_ context.Context, dest, purpose string) (*model.OTP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.otps) - 1; i >= 0; i-- {
		if o := m.otps[i]; o.Destination == dest && o.Purpose == purpose {
			return cp(o), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) CountOTPsSince(_ context.Context, dest, purpose string, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, o := range m.otps {
		if o.Destination == dest && o.Purpose == purpose && !o.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) otpByID(id string) *model.OTP {
	for _, o := range m.otps {
		if o.ID == id {
			return o
		}
	}
	return nil
}

func (m *Memory) IncrementOTPAttempts(_ context.Context, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.otpByID(id)
	if o == nil {
		return 0, ErrNotFound
	}
	o.Attempts++
	return o.Attempts, nil
}

func (m *Memory) MarkOTPVerified(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o := m.otpByID(id); o != nil {
		o.VerifiedAt = &at
		return nil
	}
	return ErrNotFound
}

func (m *Memory) ConsumeOTP(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.otpByID(id)
	if o == nil || o.VerifiedAt == nil || o.ConsumedAt != nil {
		return ErrNotFound
	}
	o.ConsumedAt = &at
	return nil
}

// ---------- Refresh tokens ----------

func (m *Memory) SaveRefreshToken(_ context.Context, t *model.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t.ID = m.id()
	m.refresh[t.TokenHash] = cp(t)
	return nil
}

func (m *Memory) GetRefreshToken(_ context.Context, hash string) (*model.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.refresh[hash]; ok {
		return cp(t), nil
	}
	return nil, ErrNotFound
}

func (m *Memory) RevokeRefreshToken(_ context.Context, hash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.refresh[hash]; ok && t.RevokedAt == nil {
		t.RevokedAt = &at
	}
	return nil
}

func (m *Memory) RevokeAllRefreshTokens(_ context.Context, userID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.refresh {
		if t.UserID == userID && t.RevokedAt == nil {
			a := at
			t.RevokedAt = &a
		}
	}
	return nil
}
