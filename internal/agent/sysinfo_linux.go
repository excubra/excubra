//go:build linux

package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/excubra/excubra/internal/wire"
)

// boxInfo reads the self-monitoring numbers from /proc and statfs.
func boxInfo(stateDir string) wire.BoxInfo {
	var b wire.BoxInfo
	var st unix.Statfs_t
	if err := unix.Statfs(stateDir, &st); err == nil {
		b.DiskTotalBytes = st.Blocks * uint64(st.Bsize) //nolint:gosec // block counts are non-negative
		b.DiskFreeBytes = st.Bavail * uint64(st.Bsize)  //nolint:gosec
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			b.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			fields := strings.Fields(v)
			if len(fields) == 0 {
				continue
			}
			kb, _ := strconv.ParseUint(fields[0], 10, 64)
			switch k {
			case "MemTotal":
				b.MemTotalBytes = kb * 1024
			case "MemAvailable":
				b.MemFreeBytes = kb * 1024
			}
		}
		_ = f.Close()
	}
	return b
}

// uptimeSeconds is the box uptime, not the process uptime.
func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(f[0], 64)
	return int64(secs)
}

func bootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// hardwareID is stable across reinstalls of the agent but changes with the board:
// machine-id plus the DMI product UUID where readable. Informational only.
func hardwareID() string {
	h := sha256.New()
	for _, p := range []string{"/etc/machine-id", "/sys/class/dmi/id/product_uuid", "/proc/device-tree/serial-number"} {
		if data, err := os.ReadFile(p); err == nil {
			h.Write(data)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
