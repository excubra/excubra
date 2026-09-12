package dnswatch

import (
	"sort"
	"strings"
	"time"
)

// Thresholds. Chrome probes three random names at start, a laptop coming out of
// sleep asks a burst of real ones; malware asks for dozens of names nobody
// registered, and a tunnel sends hundreds of long queries to one domain.
const (
	window          = 5 * time.Minute
	dgaThreshold    = 20 // random-looking names that do not exist, per client, within the window
	tunnelThreshold = 30 // long or TXT queries to one domain, per client, within the window
	maxClients      = 1024
	maxDomains      = 64 // tunnel counters per client
	longName        = 50 // characters; a real name is rarely that long
)

// counter is a sliding window of distinct keys.
type counter struct {
	items  map[string]time.Time
	pruned time.Time
	alarm  bool
}

func newCounter(now time.Time) *counter { return &counter{items: map[string]time.Time{}, pruned: now} }

func (c *counter) add(key string, now time.Time) int {
	c.items[key] = now
	if now.Sub(c.pruned) > window/4 {
		for k, t := range c.items {
			if now.Sub(t) > window {
				delete(c.items, k)
			}
		}
		c.pruned = now
		if len(c.items) == 0 {
			c.alarm = false
		}
	}
	return len(c.items)
}

// sample names a few of the keys, for a signal's detail.
func (c *counter) sample(n int) string {
	keys := make([]string, 0, len(c.items))
	for k := range c.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > n {
		keys = keys[:n]
	}
	return strings.Join(keys, ", ")
}

// client is what the sensor remembers per source address.
type client struct {
	nx      *counter            // random names that did not exist
	tunnels map[string]*counter // by registrable domain: long or TXT queries
	seen    time.Time
}

// randomLooking judges a name a domain generation algorithm would produce:
// a long label with few vowels, long consonant runs or digits mixed in. Real
// names that look like that (CDN hashes) exist and resolve; this is only
// consulted for names that do not.
func randomLooking(name string) bool {
	if strings.Contains(name, "_") || strings.HasSuffix(name, ".arpa") || strings.HasSuffix(name, ".local") {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	label := labels[0]
	if len(labels) > 2 && len(labels[1]) > len(label) {
		label = labels[1]
	}
	if len(label) < 7 {
		return false
	}
	letters, vowels, digits, run, maxRun := 0, 0, 0, 0, 0
	for _, r := range label {
		switch {
		case r >= '0' && r <= '9':
			digits++
			run = 0
		case strings.ContainsRune("aeiouy", r):
			letters++
			vowels++
			run = 0
		case r >= 'a' && r <= 'z':
			letters++
			run++
			if run > maxRun {
				maxRun = run
			}
		default:
			run = 0
		}
	}
	if letters == 0 {
		return digits >= 7
	}
	vowelRatio := float64(vowels) / float64(letters)
	return vowelRatio < 0.25 || maxRun >= 5 || (len(label) >= 12 && digits >= 3)
}

// registrable is the domain a query belongs to for the tunnel counters: the
// last two labels, three for the common second-level suffixes.
func registrable(name string) string {
	labels := strings.Split(name, ".")
	n := 2
	if len(labels) >= 3 {
		switch labels[len(labels)-2] {
		case "co", "com", "org", "net", "gov", "ac", "edu":
			n = 3
		}
	}
	if len(labels) <= n {
		return name
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// tunnelLike reports whether one query looks like a tunnel packet.
func tunnelLike(name string, qtype uint16) bool {
	if qtype == qtypeTXT || qtype == qtypeNULL {
		return true
	}
	if len(name) < longName {
		return false
	}
	labels := strings.Split(name, ".")
	long := 0
	for _, l := range labels {
		if len(l) >= 20 {
			long++
		}
	}
	return long >= 1
}
