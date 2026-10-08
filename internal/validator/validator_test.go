package validator

import "testing"

func TestNormalizePhone(t *testing.T) {
	good := map[string]string{
		"081234567890":      "+6281234567890",
		"+62 812-3456-7890": "+6281234567890",
		"6281234567890":     "+6281234567890",
		"812-3456-7890":     "+6281234567890",
	}
	for in, want := range good {
		if got, ok := NormalizePhone(in); !ok || got != want {
			t.Errorf("NormalizePhone(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "123", "0212345678", "+1 415 555 0100", "08123abc", "0812"} {
		if got, ok := NormalizePhone(in); ok {
			t.Errorf("NormalizePhone(%q) seharusnya ditolak, got %q", in, got)
		}
	}
}

func TestPassword(t *testing.T) {
	for _, p := range []string{"Rahasia@123", "Aa1!aaaa"} {
		if m := Password(p); m != "" {
			t.Errorf("Password(%q) seharusnya valid: %s", p, m)
		}
	}
	for _, p := range []string{"", "Sh0rt!A", "alllowercase1!", "ALLUPPERCASE1!", "NoDigits!!", "NoSymbol123A"} {
		if Password(p) == "" {
			t.Errorf("Password(%q) seharusnya ditolak", p)
		}
	}
}

func TestEmail(t *testing.T) {
	for _, e := range []string{"a@b.co", "budi.santoso+tag@domain.com"} {
		if !Email(e) {
			t.Errorf("%q seharusnya valid", e)
		}
	}
	for _, e := range []string{"", "a@b", "@b.com", "a b@c.com", "a@@b.com"} {
		if Email(e) {
			t.Errorf("%q seharusnya tidak valid", e)
		}
	}
}
