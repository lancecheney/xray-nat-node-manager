package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var versionCache sync.Map

type sampledMetrics struct {
	mu      sync.RWMutex
	cpu     float64
	netUp   uint64
	netDown uint64
}

var currentMetrics sampledMetrics

type serverStatus struct {
	CPU          float64                   `json:"cpu"`
	CPUCores     int                       `json:"cpuCores"`
	LogicalPro   int                       `json:"logicalPro"`
	Mem          memory                    `json:"mem"`
	Xray         xrayStatus                `json:"xray"`
	PanelVersion string                    `json:"panelVersion"`
	PanelGUID    string                    `json:"panelGuid"`
	Uptime       uint64                    `json:"uptime"`
	Loads        []float64                 `json:"loads"`
	NetIO        struct{ Up, Down uint64 } `json:"netIO"`
}

type memory struct {
	Current uint64 `json:"current"`
	Total   uint64 `json:"total"`
}

type xrayStatus struct {
	State    string `json:"state"`
	ErrorMsg string `json:"errorMsg"`
	Version  string `json:"version"`
}

func collectStatus(cfg *config) serverStatus {
	status := serverStatus{
		CPUCores: runtime.NumCPU(), LogicalPro: runtime.NumCPU(),
		PanelVersion: "xui-agent-" + version, PanelGUID: cfg.PanelGUID,
		Uptime: systemUptime(), Loads: loadAverages(),
	}
	status.Mem = memoryStatus()
	currentMetrics.mu.RLock()
	status.CPU = currentMetrics.cpu
	status.NetIO.Up = currentMetrics.netUp
	status.NetIO.Down = currentMetrics.netDown
	currentMetrics.mu.RUnlock()
	status.Xray.State = "running"
	versions := map[string]bool{}
	for _, svc := range cfg.Services {
		if len(svc.StatusCommand) > 0 {
			if err := runCommand(svc.StatusCommand, 5*time.Second); err != nil {
				status.Xray.State = "error"
				status.Xray.ErrorMsg = svc.Name + ": " + err.Error()
			}
		}
		if v := xrayVersion(svc.Binary); v != "" {
			versions[v] = true
		}
	}
	for v := range versions {
		if status.Xray.Version != "" {
			status.Xray.Version += ","
		}
		status.Xray.Version += v
	}
	return status
}

func startSystemSampler() {
	prevCPUIdle, prevCPUTotal := readCPUStat()
	prevUp, prevDown := readNetBytes()
	prevAt := time.Now()
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			idle, total := readCPUStat()
			up, down := readNetBytes()
			dt := now.Sub(prevAt).Seconds()
			cpu := 0.0
			if total > prevCPUTotal {
				totalDelta := total - prevCPUTotal
				idleDelta := idle - prevCPUIdle
				if totalDelta > 0 && idleDelta <= totalDelta {
					cpu = float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
				}
			}
			netUp, netDown := uint64(0), uint64(0)
			if dt > 0 && up >= prevUp && down >= prevDown {
				netUp = uint64(float64(up-prevUp) / dt)
				netDown = uint64(float64(down-prevDown) / dt)
			}
			currentMetrics.mu.Lock()
			currentMetrics.cpu, currentMetrics.netUp, currentMetrics.netDown = cpu, netUp, netDown
			currentMetrics.mu.Unlock()
			prevCPUIdle, prevCPUTotal = idle, total
			prevUp, prevDown, prevAt = up, down, now
		}
	}()
}

func readCPUStat() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	for i, field := range fields[1:] {
		v, _ := strconv.ParseUint(field, 10, 64)
		total += v
		if i == 3 || i == 4 {
			idle += v
		}
	}
	return idle, total
}

func readNetBytes() (up, down uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Fields(strings.ReplaceAll(line, ":", " "))
		if len(parts) < 17 || parts[0] == "lo" {
			continue
		}
		recv, errRecv := strconv.ParseUint(parts[1], 10, 64)
		sent, errSent := strconv.ParseUint(parts[9], 10, 64)
		if errRecv == nil && errSent == nil {
			down += recv
			up += sent
		}
	}
	return up, down
}

func xrayVersion(binary string) string {
	if cached, ok := versionCache.Load(binary); ok {
		return cached.(string)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil {
		versionCache.Store(binary, "unknown")
		return "unknown"
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 2 {
		versionCache.Store(binary, fields[1])
		return fields[1]
	}
	version := strings.TrimSpace(string(out))
	versionCache.Store(binary, version)
	return version
}

func systemUptime() uint64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return uint64(v)
}

func loadAverages() []float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return []float64{}
	}
	f := strings.Fields(string(b))
	out := []float64{}
	for i := 0; i < len(f) && i < 3; i++ {
		v, _ := strconv.ParseFloat(f[i], 64)
		out = append(out, v)
	}
	return out
}

func memoryStatus() memory {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return memory{}
	}
	defer f.Close()
	vals := map[string]uint64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(parts[1], 10, 64)
		vals[strings.TrimSuffix(parts[0], ":")] = v * 1024
	}
	total, available := vals["MemTotal"], vals["MemAvailable"]
	if limit := cgroupMemoryLimit(); limit > 0 && limit < total {
		total = limit
	}
	used := uint64(0)
	if total > available {
		used = total - available
	}
	if current := cgroupMemoryCurrent(); current > 0 && cgroupMemoryLimit() > 0 {
		used = current
	}
	return memory{Current: used, Total: total}
}

func cgroupMemoryLimit() uint64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err == nil {
			return v
		}
	}
	return 0
}

func cgroupMemoryCurrent() uint64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err == nil {
			return v
		}
	}
	return 0
}
