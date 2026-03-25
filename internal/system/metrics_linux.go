//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type linuxCollector struct{}

func NewMetricsCollector() MetricsCollector {
	return linuxCollector{}
}

func (linuxCollector) Snapshot() Snapshot {
	now := time.Now()
	hostname, _ := os.Hostname()
	load1, load5, load15 := readLoadAverage()
	memoryTotal, memoryUsed := readMemory()
	diskTotal, diskUsed := readRootDisk()

	snapshot := Snapshot{
		Supported:     true,
		Hostname:      hostname,
		OSName:        readOSName(),
		Uptime:        readUptime(),
		Load1:         load1,
		Load5:         load5,
		Load15:        load15,
		CPUCores:      runtime.NumCPU(),
		MemoryTotalMB: memoryTotal,
		MemoryUsedMB:  memoryUsed,
		DiskTotalGB:   diskTotal,
		DiskUsedGB:    diskUsed,
		CollectedAt:   now,
	}

	if diskTotal > 0 && diskUsed*100/diskTotal >= 85 {
		snapshot.Alerts = append(snapshot.Alerts, "Root disk usage is above 85%.")
	}
	if memoryTotal > 0 && memoryUsed*100/memoryTotal >= 85 {
		snapshot.Alerts = append(snapshot.Alerts, "Memory usage is above 85%.")
	}

	return snapshot
}

func readLoadAverage() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}

	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

func readMemory() (uint64, uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	var totalKB uint64
	var availableKB uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			totalKB = readMeminfoValue(line)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			availableKB = readMeminfoValue(line)
		}
	}

	if totalKB == 0 {
		return 0, 0
	}

	usedKB := totalKB - availableKB
	return totalKB / 1024, usedKB / 1024
}

func readMeminfoValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	value, _ := strconv.ParseUint(fields[1], 10, 64)
	return value
}

func readRootDisk() (uint64, uint64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, 0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	used := total - available

	return total / (1024 * 1024 * 1024), used / (1024 * 1024 * 1024)
}

func readUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unknown"
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "unknown"
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "unknown"
	}

	duration := time.Duration(seconds) * time.Second
	days := duration / (24 * time.Hour)
	duration -= days * 24 * time.Hour
	hours := duration / time.Hour
	duration -= hours * time.Hour
	minutes := duration / time.Minute

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func readOSName() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(line[len("PRETTY_NAME="):], "\"")
		}
	}

	return "Linux"
}
