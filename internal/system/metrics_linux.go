//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sort"
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
		TopProcesses:  readTopProcesses(),
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

func readTopProcesses() []TopProcess {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	var uptimeSeconds float64
	if data, err2 := os.ReadFile("/proc/uptime"); err2 == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			uptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	uidMap := make(map[int]string)
	if data, err2 := os.ReadFile("/etc/passwd"); err2 == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 4)
			if len(parts) >= 3 {
				if uid, err3 := strconv.Atoi(parts[2]); err3 == nil {
					uidMap[uid] = parts[0]
				}
			}
		}
	}

	var processes []TopProcess
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err2 := strconv.Atoi(entry.Name())
		if err2 != nil || pid <= 0 {
			continue
		}

		name, memKB, uid := readProcStatus(pid)
		if name == "" || memKB == 0 {
			continue
		}

		cpuPct := readProcCPUPercent(pid, uptimeSeconds)
		username := uidMap[uid]
		if username == "" {
			username = strconv.Itoa(uid)
		}

		processes = append(processes, TopProcess{
			PID:    pid,
			Name:   name,
			User:   username,
			MemMB:  memKB / 1024,
			CPUPct: cpuPct,
		})
	}

	sort.Slice(processes, func(i, j int) bool {
		if processes[i].MemMB != processes[j].MemMB {
			return processes[i].MemMB > processes[j].MemMB
		}
		return processes[i].CPUPct > processes[j].CPUPct
	})

	if len(processes) > 15 {
		processes = processes[:15]
	}
	return processes
}

func readProcStatus(pid int) (name string, memKB uint64, uid int) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Name:\t") {
			name = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ = strconv.Atoi(fields[1])
			}
		}
	}
	return
}

func readProcCPUPercent(pid int, uptimeSeconds float64) float64 {
	if uptimeSeconds <= 0 {
		return 0
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	rawStr := string(data)
	closeParen := strings.LastIndex(rawStr, ")")
	if closeParen < 0 {
		return 0
	}
	rest := strings.TrimSpace(rawStr[closeParen+1:])
	fields := strings.Fields(rest)
	// After comm: [0]=state [1]=ppid ... [11]=utime [12]=stime ... [19]=starttime
	if len(fields) < 20 {
		return 0
	}
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	starttime, _ := strconv.ParseFloat(fields[19], 64)
	const clkTck = 100.0
	elapsed := uptimeSeconds - starttime/clkTck
	if elapsed <= 0 {
		return 0
	}
	return (utime+stime) / clkTck / elapsed * 100
}
