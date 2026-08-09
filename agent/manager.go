package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type manager struct {
	cfg      *config
	services map[string]serviceConfig
	mu       sync.Mutex
	state    state
	runtime  runtimeStats
}

type runtimeStats struct {
	raw        map[string]int64
	lastOnline map[string]int64
}

func newManager(cfg *config) (*manager, error) {
	m := &manager{cfg: cfg, services: map[string]serviceConfig{}}
	m.runtime.raw = map[string]int64{}
	m.runtime.lastOnline = map[string]int64{}
	for _, svc := range cfg.Services {
		m.services[svc.Name] = svc
	}
	m.state = state{NextID: 1, KnownTags: map[string][]string{}, LastOnline: map[string]int64{}}
	if b, err := os.ReadFile(cfg.StatePath); err == nil {
		if err := json.Unmarshal(b, &m.state); err != nil {
			return nil, fmt.Errorf("decode state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if m.state.NextID < 1 {
		m.state.NextID = 1
	}
	if m.state.KnownTags == nil {
		m.state.KnownTags = map[string][]string{}
	}
	if m.state.LastOnline == nil {
		m.state.LastOnline = map[string]int64{}
	}
	return m, nil
}

func (m *manager) snapshot() state {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneState(m.state)
}

func cloneState(in state) state {
	b, _ := json.Marshal(in)
	var out state
	_ = json.Unmarshal(b, &out)
	return out
}

func (m *manager) adopt() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	next := cloneState(m.state)
	existingIDs := map[string]int{}
	for _, rec := range next.Inbounds {
		existingIDs[rec.Service+"\x00"+rec.Inbound.Tag] = rec.Inbound.ID
	}
	next.Inbounds = nil
	for _, svc := range m.cfg.Services {
		root, err := readObject(svc.ConfigPath)
		if err != nil {
			return fmt.Errorf("adopt %s: %w", svc.Name, err)
		}
		items, _ := root["inbounds"].([]any)
		ignored := stringSet(svc.IgnoreTags)
		for _, item := range items {
			raw, ok := item.(map[string]any)
			if !ok {
				continue
			}
			tag, _ := raw["tag"].(string)
			if tag == "" || ignored[tag] {
				continue
			}
			rec, err := inboundFromRaw(raw, svc.Name)
			if err != nil {
				return fmt.Errorf("adopt %s inbound %q: %w", svc.Name, tag, err)
			}
			if id := existingIDs[svc.Name+"\x00"+tag]; id > 0 {
				rec.Inbound.ID = id
			} else {
				rec.Inbound.ID = next.NextID
				next.NextID++
			}
			next.Inbounds = append(next.Inbounds, rec)
			next.KnownTags[svc.Name] = appendUnique(next.KnownTags[svc.Name], tag)
		}
	}
	sort.Slice(next.Inbounds, func(i, j int) bool { return next.Inbounds[i].Inbound.ID < next.Inbounds[j].Inbound.ID })
	if err := m.saveState(next); err != nil {
		return err
	}
	m.state = next
	return nil
}

func inboundFromRaw(raw map[string]any, service string) (inboundRecord, error) {
	port, err := jsonNumberInt(raw["port"])
	if err != nil {
		return inboundRecord{}, fmt.Errorf("port: %w", err)
	}
	streamSettings, err := panelStreamSettings(raw["streamSettings"])
	if err != nil {
		return inboundRecord{}, err
	}
	ib := inbound{
		Enable:            true,
		SubSortIndex:      1,
		Listen:            stringValue(raw["listen"]),
		Port:              port,
		Protocol:          stringValue(raw["protocol"]),
		Tag:               stringValue(raw["tag"]),
		Remark:            stringValue(raw["tag"]),
		Settings:          normalizedSettings(raw["settings"]),
		StreamSettings:    streamSettings,
		Sniffing:          objectString(raw["sniffing"]),
		ShareAddrStrategy: "node",
	}
	known := stringSet([]string{"listen", "port", "protocol", "tag", "settings", "streamSettings", "sniffing"})
	extra := map[string]json.RawMessage{}
	for k, v := range raw {
		if known[k] {
			continue
		}
		b, _ := json.Marshal(v)
		extra[k] = b
	}
	return inboundRecord{Inbound: ib, Service: service, Extra: extra}, nil
}

func panelStreamSettings(value any) (string, error) {
	stream, ok := value.(map[string]any)
	if !ok {
		return objectString(value), nil
	}
	b, err := json.Marshal(stream)
	if err != nil {
		return "", err
	}
	var panel map[string]any
	if err := json.Unmarshal(b, &panel); err != nil {
		return "", err
	}
	if stringValue(panel["security"]) == "reality" {
		reality, _ := panel["realitySettings"].(map[string]any)
		if reality != nil {
			settings, _ := reality["settings"].(map[string]any)
			if settings == nil {
				settings = map[string]any{}
				reality["settings"] = settings
			}
			if stringValue(settings["publicKey"]) == "" {
				privateKey := stringValue(reality["privateKey"])
				if privateKey != "" {
					publicKey, err := realityPublicKey(privateKey)
					if err != nil {
						return "", fmt.Errorf("derive Reality public key: %w", err)
					}
					settings["publicKey"] = publicKey
				}
			}
			if stringValue(settings["fingerprint"]) == "" {
				settings["fingerprint"] = "chrome"
			}
			if _, exists := settings["serverName"]; !exists {
				settings["serverName"] = ""
			}
			if _, exists := settings["spiderX"]; !exists {
				settings["spiderX"] = "/"
			}
			if _, exists := settings["mldsa65Verify"]; !exists {
				settings["mldsa65Verify"] = ""
			}
		}
	}
	return objectString(panel), nil
}

func realityPublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func normalizedSettings(v any) string {
	settings, ok := v.(map[string]any)
	if !ok {
		return objectString(v)
	}
	clients, _ := settings["clients"].([]any)
	for _, item := range clients {
		c, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, exists := c["enable"]; !exists {
			c["enable"] = true
		}
		for _, key := range []string{"limitIp", "totalGB", "expiryTime", "tgId", "reset"} {
			if _, exists := c[key]; !exists {
				c[key] = 0
			}
		}
	}
	return objectString(settings)
}

func objectString(v any) string {
	if v == nil {
		return "{}"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func jsonNumberInt(v any) (int, error) {
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case json.Number:
		i, err := strconv.Atoi(n.String())
		return i, err
	default:
		return 0, fmt.Errorf("unexpected %T", v)
	}
}

func readObject(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	return root, nil
}

func (m *manager) check() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, svc := range m.cfg.Services {
		if _, err := os.Stat(svc.Binary); err != nil {
			return fmt.Errorf("service %s binary: %w", svc.Name, err)
		}
		if err := validateXrayConfig(svc, svc.ConfigPath); err != nil {
			return err
		}
	}
	return nil
}

func validateXrayConfig(svc serviceConfig, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, svc.Binary, "run", "-test", "-c", path)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("validate %s: %w", svc.Name, ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("validate %s: %w: %s", svc.Name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *manager) mutate(fn func(*state) (map[string]bool, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := cloneState(m.state)
	affected, err := fn(&next)
	if err != nil {
		return err
	}
	if len(affected) == 0 {
		return nil
	}
	if err := m.apply(next, affected); err != nil {
		return err
	}
	m.state = next
	return nil
}

type stagedConfig struct {
	service  serviceConfig
	temp     string
	backup   string
	mode     os.FileMode
	replaced bool
}

func (m *manager) apply(next state, affected map[string]bool) error {
	staged := make([]*stagedConfig, 0, len(affected))
	cleanup := func() {
		for _, s := range staged {
			if s.temp != "" {
				_ = os.Remove(s.temp)
			}
		}
	}
	defer cleanup()

	for _, svc := range m.cfg.Services {
		if !affected[svc.Name] {
			continue
		}
		data, mode, err := m.renderService(next, svc)
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(svc.ConfigPath), ".xui-agent-candidate-*.json")
		if err != nil {
			return err
		}
		tempPath := tmp.Name()
		if err := tmp.Chmod(mode); err == nil {
			_, err = tmp.Write(data)
		}
		closeErr := tmp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
			return err
		}
		if closeErr != nil {
			_ = os.Remove(tempPath)
			return closeErr
		}
		if err := validateXrayConfig(svc, tempPath); err != nil {
			_ = os.Remove(tempPath)
			return err
		}
		staged = append(staged, &stagedConfig{service: svc, temp: tempPath, mode: mode})
	}

	for _, s := range staged {
		// Single rotating backup per config: overwrite the previous
		// last-good file so backups never accumulate on disk.
		s.backup = s.service.ConfigPath + ".xui-agent.bak"
		if err := copyFileAtomic(s.service.ConfigPath, s.backup, s.mode); err != nil {
			m.rollback(staged)
			return fmt.Errorf("backup %s: %w", s.service.Name, err)
		}
		if err := os.Rename(s.temp, s.service.ConfigPath); err != nil {
			m.rollback(staged)
			return fmt.Errorf("replace %s: %w", s.service.Name, err)
		}
		s.temp = ""
		s.replaced = true
	}
	for _, s := range staged {
		if err := runCommand(s.service.RestartCommand, 30*time.Second); err != nil {
			m.rollback(staged)
			return fmt.Errorf("restart %s: %w", s.service.Name, err)
		}
	}
	if err := m.saveState(next); err != nil {
		m.rollback(staged)
		return err
	}
	return nil
}

func (m *manager) rollback(staged []*stagedConfig) {
	for _, s := range staged {
		if s.replaced && s.backup != "" {
			_ = copyFile(s.backup, s.service.ConfigPath, s.mode)
		}
	}
	for _, s := range staged {
		if s.replaced {
			_ = runCommand(s.service.RestartCommand, 30*time.Second)
		}
	}
}

func (m *manager) renderService(next state, svc serviceConfig) ([]byte, os.FileMode, error) {
	root, err := readObject(svc.ConfigPath)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s config: %w", svc.Name, err)
	}
	info, err := os.Stat(svc.ConfigPath)
	if err != nil {
		return nil, 0, err
	}
	rewriteInboundTagReferences(root, next.TagRenames[svc.Name])
	known := stringSet(next.KnownTags[svc.Name])
	ignored := stringSet(svc.IgnoreTags)
	current, _ := root["inbounds"].([]any)
	out := make([]any, 0, len(current)+len(next.Inbounds))
	for _, item := range current {
		raw, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		tag := stringValue(raw["tag"])
		if ignored[tag] || !known[tag] {
			out = append(out, item)
		}
	}
	for _, rec := range next.Inbounds {
		if rec.Service == svc.Name && rec.Inbound.Enable {
			raw, err := rawInbound(rec)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, raw)
		}
	}
	root["inbounds"] = out
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	b = append(b, '\n')
	return b, info.Mode().Perm(), nil
}

func rewriteInboundTagReferences(root map[string]any, renames map[string]string) {
	if len(renames) == 0 {
		return
	}
	routing, _ := root["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	for _, item := range rules {
		rule, _ := item.(map[string]any)
		tags, _ := rule["inboundTag"].([]any)
		for i, value := range tags {
			tag, _ := value.(string)
			if renamed, ok := renames[tag]; ok {
				tags[i] = renamed
			}
		}
	}
}

func rawInbound(rec inboundRecord) (map[string]any, error) {
	raw := map[string]any{}
	for k, v := range rec.Extra {
		var decoded any
		if err := json.Unmarshal(v, &decoded); err != nil {
			return nil, fmt.Errorf("decode extra field %s: %w", k, err)
		}
		raw[k] = decoded
	}
	ib := rec.Inbound
	raw["listen"] = ib.Listen
	raw["port"] = ib.Port
	raw["protocol"] = ib.Protocol
	raw["tag"] = ib.Tag
	for key, value := range map[string]string{
		"settings": ib.Settings, "streamSettings": ib.StreamSettings, "sniffing": ib.Sniffing,
	} {
		var decoded any
		if strings.TrimSpace(value) == "" {
			decoded = map[string]any{}
		} else if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			return nil, fmt.Errorf("inbound %q invalid %s: %w", ib.Tag, key, err)
		}
		if key == "settings" {
			decoded = xraySettings(ib.Protocol, decoded)
		}
		raw[key] = decoded
	}
	return raw, nil
}

// panelOnly fields are 3x-ui metadata that must never be written into the
// Xray config. Known protocols are filtered by an allowlist; unknown protocols
// fall back to stripping these fields so nothing panel-specific leaks through.
var panelOnlyFields = stringSet([]string{
	"email", "level", "enable", "limitIp", "totalGB", "expiryTime",
	"tgId", "reset", "subId", "comment", "group",
})

func xraySettings(protocol string, decoded any) any {
	settings, ok := decoded.(map[string]any)
	if !ok {
		return decoded
	}
	items, ok := settings["clients"].([]any)
	if !ok {
		return decoded
	}
	allowed := map[string]bool{"email": true, "level": true}
	known := false
	switch protocol {
	case "vless":
		known = true
		allowed["id"], allowed["flow"], allowed["encryption"] = true, true, true
	case "hysteria":
		known = true
		allowed["auth"] = true
	case "vmess":
		known = true
		allowed["id"], allowed["alterId"], allowed["security"] = true, true, true
	case "trojan":
		known = true
		allowed["password"] = true
	case "shadowsocks":
		known = true
		allowed["password"], allowed["method"] = true, true
	}
	filtered := make([]any, 0, len(items))
	for _, item := range items {
		c, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if enabled, exists := c["enable"].(bool); exists && !enabled {
			continue
		}
		out := map[string]any{}
		for key, value := range c {
			if known {
				if allowed[key] {
					out[key] = value
				}
			} else if !panelOnlyFields[key] {
				out[key] = value
			}
		}
		filtered = append(filtered, out)
	}
	clone := make(map[string]any, len(settings))
	for key, value := range settings {
		clone[key] = value
	}
	clone["clients"] = filtered
	return clone
}

func (m *manager) saveState(next state) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(m.cfg.StatePath), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.cfg.StatePath), ".state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(b)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpPath, m.cfg.StatePath)
}

func runCommand(argv []string, timeout time.Duration) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// copyFileAtomic replaces dst with a copy of src via a temp file + rename, so
// dst always holds either its previous content or the new copy, never a
// partially-written file.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".xui-agent-backup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	_, copyErr := io.Copy(tmp, in)
	closeErr := tmp.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmpPath, dst)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func stringSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
