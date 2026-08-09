package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type config struct {
	Listen      string          `json:"listen"`
	Token       string          `json:"token"`
	PanelGUID   string          `json:"panelGuid"`
	StatePath   string          `json:"statePath"`
	TLSCertFile string          `json:"tlsCertFile"`
	TLSKeyFile  string          `json:"tlsKeyFile"`
	Services    []serviceConfig `json:"services"`
}

type serviceConfig struct {
	Name           string   `json:"name"`
	Binary         string   `json:"binary"`
	ConfigPath     string   `json:"configPath"`
	APIEndpoint    string   `json:"apiEndpoint"`
	RestartCommand []string `json:"restartCommand"`
	StatusCommand  []string `json:"statusCommand"`
	IgnoreTags     []string `json:"ignoreTags"`
	Default        bool     `json:"default"`
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Listen == "" || cfg.StatePath == "" || cfg.Token == "" || len(cfg.Services) == 0 {
		return nil, errors.New("listen, token, statePath, and services are required")
	}
	if len(cfg.Token) < 24 {
		return nil, errors.New("token must contain at least 24 characters")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, errors.New("tlsCertFile and tlsKeyFile must be configured together")
	}
	seen := map[string]bool{}
	defaults := 0
	for i := range cfg.Services {
		s := &cfg.Services[i]
		if s.Name == "" || s.Binary == "" || s.ConfigPath == "" || len(s.RestartCommand) == 0 {
			return nil, fmt.Errorf("service %d requires name, binary, configPath, and restartCommand", i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("duplicate service %q", s.Name)
		}
		seen[s.Name] = true
		if s.Default {
			defaults++
		}
		for _, p := range []string{s.Binary, s.ConfigPath} {
			if !filepath.IsAbs(p) {
				return nil, fmt.Errorf("service %q path %q must be absolute", s.Name, p)
			}
		}
		if s.APIEndpoint != "" && !strings.HasPrefix(s.APIEndpoint, "127.0.0.1:") && !strings.HasPrefix(s.APIEndpoint, "localhost:") {
			return nil, fmt.Errorf("service %q API endpoint must be loopback", s.Name)
		}
	}
	if defaults != 1 {
		return nil, errors.New("exactly one service must be marked default")
	}
	if cfg.PanelGUID == "" {
		cfg.PanelGUID, err = randomGUID()
		if err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

func randomGUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
