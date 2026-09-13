package console

import "testing"

func TestTileOrigin(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://tile.openstreetmap.org/{z}/{x}/{y}.png", "https://tile.openstreetmap.org"},
		{"https://tiles.example.test:8443/a/{z}/{x}/{y}@2x.png", "https://tiles.example.test:8443"},
		{"http://192.0.2.10:8080/{z}/{x}/{y}.png", "http://192.0.2.10:8080"},
		{"", ""},
		{"{z}/{x}/{y}.png", ""},
		{"javascript:alert(1)", ""},
		{"ftp://example.test/{z}.png", ""},
	} {
		if got := tileOrigin(c.in); got != c.want {
			t.Errorf("tileOrigin(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
