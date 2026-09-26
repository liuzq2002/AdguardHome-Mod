//go:build !linux

package snifilter

import (
	"context"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
)

// platform is the platform-specific state of the SNI filter.
type platform struct{}

// startFirewall returns an error, as the SNI filtering is only supported on
// Linux.
func (f *Filter) startFirewall(_ context.Context) (err error) {
	return aghos.Unsupported("sni filter")
}

// stopFirewall does nothing.
func (f *Filter) stopFirewall(_ context.Context) {}
