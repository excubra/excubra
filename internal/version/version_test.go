package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Semver
		ok   bool
	}{
		{"1.2.3", Semver{1, 2, 3}, true},
		{"v1.2.3", Semver{1, 2, 3}, true},
		{"1.2.3-rc1", Semver{1, 2, 3}, true},
		{"1.2.3+abc", Semver{1, 2, 3}, true},
		{"0.0.0-dev+abc", Semver{0, 0, 0}, true},
		{"1.2", Semver{}, false},
		{"a.b.c", Semver{}, false},
		{"", Semver{}, false},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if (err == nil) != c.ok {
			t.Errorf("Parse(%q): ok=%v, want %v (err=%v)", c.in, err == nil, c.ok, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCompatible(t *testing.T) {
	cases := []struct {
		agent, server string
		want          bool
	}{
		{"1.4.0", "1.4.9", true},
		{"1.2.0", "1.4.0", true},
		{"1.6.0", "1.4.0", true},
		{"1.1.0", "1.4.0", false},
		{"1.7.0", "1.4.0", false},
		{"2.4.0", "1.4.0", false},
		{"0.0.0", "0.0.0", true},
	}
	for _, c := range cases {
		a, _ := Parse(c.agent)
		s, _ := Parse(c.server)
		if got := Compatible(a, s); got != c.want {
			t.Errorf("Compatible(%s, %s) = %v, want %v", c.agent, c.server, got, c.want)
		}
	}
}
