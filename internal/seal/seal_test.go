package seal

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	box, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(Public(box), []byte("api-token-123"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Open(box, blob)
	if err != nil || string(msg) != "api-token-123" {
		t.Fatalf("open: %q %v", msg, err)
	}
	other, _ := GenerateKey()
	if _, err := Open(other, blob); err == nil {
		t.Fatal("another box must not open it")
	}
	// one flipped byte in the ciphertext
	raw := []byte(blob)
	raw[len(raw)-3] ^= 1
	if _, err := Open(box, string(raw)); err == nil {
		t.Fatal("damaged blob opened")
	}
	if fp := Fingerprint(Public(box)); len(fp) != 19 || strings.Count(fp, " ") != 3 {
		t.Fatalf("fingerprint %q", fp)
	}
	if Fingerprint("nope") != "" {
		t.Fatal("bad key must have no fingerprint")
	}
}

// web/src/lib/seal.ts, run under Node's WebCrypto, produced testdata/browser.json:
// the box key, the blob and the message. Both sides must keep opening each other's
// output; regenerate the file when the construction changes (and bump Info).
func TestOpensBrowserFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/browser.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Priv, Pub, Blob, Msg, Fingerprint string
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(fx.Priv)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if Public(priv) != fx.Pub {
		t.Fatal("fixture key pair does not match")
	}
	msg, err := Open(priv, fx.Blob)
	if err != nil || string(msg) != fx.Msg {
		t.Fatalf("browser blob: %q %v", msg, err)
	}
	if Fingerprint(fx.Pub) != fx.Fingerprint {
		t.Fatalf("fingerprint differs: go %q browser %q", Fingerprint(fx.Pub), fx.Fingerprint)
	}
}
