package agent

import (
	"sort"
	"strconv"
)

// parseCaps decodes the hex capability mask of /proc/self/status into the names
// the console shows; unknown bits are left out.
func parseCaps(hexMask string) []string {
	mask, err := strconv.ParseUint(hexMask, 16, 64)
	if err != nil {
		return nil
	}
	var out []string
	for bit, name := range capNames {
		if mask&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
