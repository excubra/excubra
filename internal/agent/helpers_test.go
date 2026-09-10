package agent

import (
	"log/slog"

	"github.com/excubra/excubra/internal/agent/discovery"
)

func discoveryForTest() *discovery.Discovery { return discovery.New(slog.Default()) }
