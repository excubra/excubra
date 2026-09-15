package console

import "testing"

// A redirect target must stay inside this console. The targets are built in
// code, but out of ids that arrive in a form, and "//example.test" reads like a
// path and travels like a different site.
func TestOwnPath(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/tenants/ten_a", "/tenants/ten_a"},
		{"/devices/dev_1?tab=patch", "/devices/dev_1?tab=patch"},
		{"//example.test/", "/"},
		{"https://example.test/", "/"},
		{"tenants/ten_a", "/"},
		{"", "/"},
		{`/\example.test`, "/"},
	} {
		if got := ownPath(c.in); got != c.want {
			t.Errorf("ownPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
