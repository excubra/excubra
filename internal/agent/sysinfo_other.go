//go:build !linux

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/excubra/excubra/internal/wire"
)

var processStart = time.Now()

func boxInfo(stateDir string) wire.BoxInfo {
	var b wire.BoxInfo
	var st unix.Statfs_t
	if err := unix.Statfs(stateDir, &st); err == nil {
		b.DiskTotalBytes = st.Blocks * uint64(st.Bsize) //nolint:gosec
		b.DiskFreeBytes = st.Bavail * uint64(st.Bsize)  //nolint:gosec
	}
	return b
}

func uptimeSeconds() int64 { return int64(time.Since(processStart).Seconds()) }

// capNames and the unit request are Linux matters; a development machine has neither.
var capNames = map[uint]string{10: "CAP_NET_BIND_SERVICE", 13: "CAP_NET_RAW", 12: "CAP_NET_ADMIN"}

func effectiveCaps() []string { return nil }

func requestUnit(string) {}

func bootID() string { return "" }

func hardwareID() string {
	h := sha256.New()
	name, _ := os.Hostname()
	h.Write([]byte(name))
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if len(i.HardwareAddr) == 6 && i.Flags&net.FlagLoopback == 0 {
				h.Write(i.HardwareAddr)
				break
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
