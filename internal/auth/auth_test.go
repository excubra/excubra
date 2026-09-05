package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("format: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("right password refused")
	}
	if VerifyPassword(h, "correct horse batter") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("garbage", "x") || VerifyPassword("pbkdf2-sha256$10$AA$AA", "x") {
		t.Fatal("garbage hash accepted")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if p := RandomPassword(); len(p) != 20 || strings.ContainsAny(p, "0O1lI") {
		t.Fatalf("random password: %q", p)
	}
}

// RFC 6238 test vector: secret "12345678901234567890", SHA-1, T=59 → 287082 (8 digits 94287082).
func TestTOTPVector(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	code, err := TOTPCode(secret, Counter(time.Unix(59, 0)))
	if err != nil || code != "287082" {
		t.Fatalf("code = %s, %v", code, err)
	}
	code, _ = TOTPCode(secret, Counter(time.Unix(1111111109, 0)))
	if code != "081804" {
		t.Fatalf("code at 1111111109 = %s", code)
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	if len(secret) != 32 {
		t.Fatalf("secret length %d", len(secret))
	}
	now := time.Unix(1_757_000_000, 0)
	code, _ := TOTPCode(secret, Counter(now))
	c, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || c != Counter(now) {
		t.Fatalf("verify: %v %d", ok, c)
	}
	if _, ok := VerifyTOTP(secret, code, now, c); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(30*time.Second), 0); !ok {
		t.Fatal("previous step refused inside the window")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(90*time.Second), 0); ok {
		t.Fatal("code accepted outside the window")
	}
	if _, ok := VerifyTOTP(secret, "000000", now, 0); ok {
		t.Fatal("wrong code accepted")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
	uri := TOTPURI("EX0", "jeremia", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/EX0:jeremia?") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("uri: %s", uri)
	}
}
