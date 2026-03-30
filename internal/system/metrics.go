package system

import "time"

type TopProcess struct {
	PID    int
	Name   string
	User   string
	MemMB  uint64
	CPUPct float64
}

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
	TopProcesses   []TopProcess
}

type MetricsCollector interface {
	Snapshot() Snapshot
}
