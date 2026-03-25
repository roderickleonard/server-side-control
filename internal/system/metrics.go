package system

import "time"

type Snapshot struct {
	Supported      bool
	Hostname       string
	OSName         string
	Uptime         string
	Load1          float64
	Load5          float64
	Load15         float64
	CPUCores       int
	MemoryTotalMB  uint64
	MemoryUsedMB   uint64
	DiskTotalGB    uint64
	DiskUsedGB     uint64
	CollectedAt    time.Time
	Alerts         []string
}

type MetricsCollector interface {
	Snapshot() Snapshot
}
