//go:build !linux

package sentinel

import (
	"context"

	"github.com/excubra/excubra/internal/agent/discovery"
)

// Off Linux there is no route table to read and no packet socket: the decoys
// still listen (on whatever LAN a test gives them) and count on their own.

func platformSelf() Self { return Self{} }

func platformWatch(context.Context, func([]byte)) error { return discovery.ErrUnsupported }
