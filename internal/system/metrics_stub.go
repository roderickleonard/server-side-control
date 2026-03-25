//go:build !linux

package system

import "time"

type stubCollector struct{}

func NewMetricsCollector() MetricsCollector {
	return stubCollector{}
}

func (stubCollector) Snapshot() Snapshot {
	return Snapshot{
		Supported:   false,
		OSName:      "unsupported-host",
		CollectedAt: time.Now(),
		Alerts: []string{
			"Linux metrics are only available on Ubuntu target hosts.",
		},
	}
}
