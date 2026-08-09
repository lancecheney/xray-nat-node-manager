package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type statsQuery struct {
	Stats []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	} `json:"stat"`
}

func (m *manager) startStatsSampler() {
	_ = m.refreshStats()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_ = m.refreshStats()
		}
	}()
}

func (m *manager) refreshStats() error {
	all := map[string]int64{}
	for _, svc := range m.cfg.Services {
		if svc.APIEndpoint == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cmd := exec.CommandContext(ctx, svc.Binary, "api", "statsquery", "--server="+svc.APIEndpoint, "-pattern", "", "-reset=false")
		out, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		var query statsQuery
		if err := json.Unmarshal(out, &query); err != nil {
			continue
		}
		for _, stat := range query.Stats {
			all[svc.Name+"\x00"+stat.Name] = stat.Value
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UnixMilli()
	for i := range m.state.Inbounds {
		rec := &m.state.Inbounds[i]
		ib := &rec.Inbound
		prefix := rec.Service + "\x00"
		upName := prefix + "inbound>>>" + ib.Tag + ">>>traffic>>>uplink"
		downName := prefix + "inbound>>>" + ib.Tag + ">>>traffic>>>downlink"
		ib.Up, ib.Down = all[upName], all[downName]

		clients, _, err := settingsClients(ib)
		if err != nil {
			continue
		}
		rows := make([]clientTraffic, 0, len(clients))
		for j, c := range clients {
			email := clientEmail(c)
			if email == "" {
				continue
			}
			uName := prefix + "user>>>" + email + ">>>traffic>>>uplink"
			dName := prefix + "user>>>" + email + ">>>traffic>>>downlink"
			u, d := all[uName], all[dName]
			key := rec.Service + "\x00" + email
			if u > m.runtime.raw[uName] || d > m.runtime.raw[dName] {
				m.runtime.lastOnline[key] = now
			}
			row := trafficFromClient(j+1, ib.ID, c)
			row.Up, row.Down = u, d
			row.LastOnline = m.runtime.lastOnline[key]
			rows = append(rows, row)
		}
		ib.ClientStats = rows
	}
	m.runtime.raw = all
	return nil
}

func trafficFromClient(id, inboundID int, c map[string]any) clientTraffic {
	return clientTraffic{
		ID:         id,
		InboundID:  inboundID,
		Enable:     boolValue(c["enable"], true),
		Email:      clientEmail(c),
		UUID:       stringValue(c["id"]),
		SubID:      stringValue(c["subId"]),
		ExpiryTime: int64Value(c["expiryTime"]),
		Total:      int64Value(c["totalGB"]),
		Reset:      int(int64Value(c["reset"])),
	}
}

func boolValue(v any, fallback bool) bool {
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

func int64Value(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		v, _ := n.Int64()
		return v
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}

func (m *manager) onlineByGUID() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-20 * time.Second).UnixMilli()
	seen := map[string]bool{}
	online := []string{}
	for _, rec := range m.state.Inbounds {
		for _, row := range rec.Inbound.ClientStats {
			if row.LastOnline >= cutoff && !seen[strings.ToLower(row.Email)] {
				seen[strings.ToLower(row.Email)] = true
				online = append(online, row.Email)
			}
		}
	}
	return map[string][]string{m.cfg.PanelGUID: online}
}

func (m *manager) lastOnline() map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int64{}
	for _, rec := range m.state.Inbounds {
		for _, row := range rec.Inbound.ClientStats {
			if row.LastOnline > out[row.Email] {
				out[row.Email] = row.LastOnline
			}
		}
	}
	return out
}

func (m *manager) resetTraffic(email string, inboundID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, svc := range m.cfg.Services {
		if svc.APIEndpoint == "" {
			continue
		}
		patterns := []string{}
		if email != "" {
			patterns = append(patterns, "user>>>"+email+">>>traffic>>>")
		} else if inboundID > 0 {
			idx := recordIndex(&m.state, inboundID)
			if idx >= 0 && m.state.Inbounds[idx].Service == svc.Name {
				patterns = append(patterns, "inbound>>>"+m.state.Inbounds[idx].Inbound.Tag+">>>traffic>>>")
			}
		} else {
			patterns = append(patterns, "")
		}
		for _, pattern := range patterns {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			cmd := exec.CommandContext(ctx, svc.Binary, "api", "statsquery", "--server="+svc.APIEndpoint, "-pattern", pattern, "-reset=true")
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				return fmt.Errorf("reset stats for %s: %w: %s", svc.Name, err, strings.TrimSpace(string(out)))
			}
		}
	}
	m.zeroLocalStats(email, inboundID)
	return nil
}

// zeroLocalStats clears the locally cached traffic counters that match the
// reset scope, so the panel does not keep showing stale values until the next
// sampler tick. It must be called with m.mu held.
func (m *manager) zeroLocalStats(email string, inboundID int) {
	resetAll := email == "" && inboundID == 0
	for i := range m.state.Inbounds {
		rec := &m.state.Inbounds[i]
		ib := &rec.Inbound
		if resetAll || (inboundID > 0 && ib.ID == inboundID) {
			ib.Up, ib.Down = 0, 0
		}
		for j := range ib.ClientStats {
			row := &ib.ClientStats[j]
			switch {
			case email != "" && strings.EqualFold(row.Email, email):
				row.Up, row.Down = 0, 0
			case resetAll:
				row.Up, row.Down = 0, 0
			case inboundID > 0 && row.InboundID == inboundID:
				row.Up, row.Down = 0, 0
			}
		}
	}
	if resetAll {
		m.runtime.raw = map[string]int64{}
		return
	}
	if email != "" {
		prefix := "\x00user>>>" + email + ">>>traffic>>>"
		for key := range m.runtime.raw {
			if strings.Contains(key, prefix) {
				m.runtime.raw[key] = 0
			}
		}
	}
	if inboundID > 0 {
		idx := recordIndex(&m.state, inboundID)
		if idx >= 0 {
			prefix := m.state.Inbounds[idx].Service + "\x00inbound>>>" + m.state.Inbounds[idx].Inbound.Tag + ">>>traffic>>>"
			for key := range m.runtime.raw {
				if strings.Contains(key, prefix) {
					m.runtime.raw[key] = 0
				}
			}
		}
	}
}
