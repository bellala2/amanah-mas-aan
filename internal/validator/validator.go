package validator

import (
	"regexp"
	"strings"
	"unicode"
)

type Fields map[string]string

// Add hanya menyimpan pesan pertama per field.
func (f Fields) Add(field, msg string) {
	if _, ok := f[field]; !ok {
		f[field] = msg
	}
}

var (
	emailRe    = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}$`)
	usernameRe = regexp.MustCompile(`^[a-z0-9_.]{3,30}$`)
)

func Email(s string) bool { return len(s) <= 254 && emailRe.MatchString(s) }

func Username(s string) bool { return usernameRe.MatchString(s) }

// NormalizePhone menerima "0812...", "62812...", "+62 812-3456-7890", "812..." dan
// menghasilkan format E.164 "+62812...". Hanya nomor seluler Indonesia (awalan 8).
func NormalizePhone(raw string) (string, bool) {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' || r == ' ' || r == '-' || r == '(' || r == ')':
		default:
			return "", false
		}
	}
	d := b.String()
	switch {
	case strings.HasPrefix(d, "62"):
		d = d[2:]
	case strings.HasPrefix(d, "0"):
		d = d[1:]
	}
	if !strings.HasPrefix(d, "8") || len(d) < 9 || len(d) > 12 {
		return "", false
	}
	return "+62" + d, true
}

// Password mengembalikan pesan error ("" jika valid).
// Aturan sesuai UI: min 8 karakter, huruf besar & kecil, angka, simbol khusus.
// Maks 72 byte karena batas bcrypt.
func Password(p string) string {
	if len(p) < 8 {
		return "Kata sandi minimal 8 karakter"
	}
	if len(p) > 72 {
		return "Kata sandi maksimal 72 karakter"
	}
	var up, lo, di, sy bool
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			up = true
		case unicode.IsLower(r):
			lo = true
		case unicode.IsDigit(r):
			di = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			sy = true
		}
	}
	switch {
	case !up || !lo:
		return "Kata sandi harus mengandung huruf besar dan huruf kecil"
	case !di:
		return "Kata sandi harus mengandung angka (0-9)"
	case !sy:
		return "Kata sandi harus mengandung simbol khusus (@#$!)"
	}
	return ""
}
