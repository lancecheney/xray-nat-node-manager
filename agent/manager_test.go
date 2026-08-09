package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testManager(t *testing.T) (*manager, *config, string) {
	t.Helper()
	dir := t.TempDir()
	xray := filepath.Join(dir, "xray")
	script := "#!/bin/sh\ncase \"$*\" in *-test*) grep -Eq '\"reject\"[[:space:]]*:[[:space:]]*true' \"$4\" && exit 1; exit 0;; esac\nexit 0\n"
	if err := os.WriteFile(xray, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "xray.json")
	xrayConfig := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "existing", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": "old-id", "email": "old", "flow": "xtls-rprx-vision"}}},
			"streamSettings": map[string]any{"network": "raw"}, "sniffing": map[string]any{"enabled": false},
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	b, _ := json.Marshal(xrayConfig)
	if err := os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config{
		Listen: "127.0.0.1:0", Token: strings.Repeat("t", 32), PanelGUID: "test-guid",
		StatePath: filepath.Join(dir, "state.json"),
		Services:  []serviceConfig{{Name: "main", Binary: xray, ConfigPath: configPath, Default: true, RestartCommand: []string{xray, "restart"}}},
	}
	m, err := newManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m, cfg, configPath
}

func TestAdoptAndClientMutationPreservesConfig(t *testing.T) {
	m, _, path := testManager(t)
	if err := m.adopt(); err != nil {
		t.Fatal(err)
	}
	list := m.inbounds()
	if len(list) != 1 || list[0].Tag != "existing" {
		t.Fatalf("unexpected adopted inbounds: %+v", list)
	}
	c := client{ID: "new-id", Email: "new", Flow: "xtls-rprx-vision", Enable: true, TotalGB: 99, LimitIP: 2}
	if err := m.addClient(c, []int{list[0].ID}); err != nil {
		t.Fatal(err)
	}
	root, err := readObject(path)
	if err != nil {
		t.Fatal(err)
	}
	if root["outbounds"] == nil || root["log"] == nil {
		t.Fatal("unmanaged root config was not preserved")
	}
	inbounds := root["inbounds"].([]any)
	settings := inbounds[0].(map[string]any)["settings"].(map[string]any)
	clients := settings["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("got %d clients", len(clients))
	}
	newClient := clients[1].(map[string]any)
	if _, exists := newClient["totalGB"]; exists {
		t.Fatal("panel-only totalGB leaked into Xray config")
	}
	if _, exists := newClient["limitIp"]; exists {
		t.Fatal("panel-only limitIp leaked into Xray config")
	}
}

func TestPanelStreamSettingsAddsRealityShareMetadata(t *testing.T) {
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	wantPublicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	raw := map[string]any{
		"network":  "tcp",
		"security": "reality",
		"realitySettings": map[string]any{
			"privateKey": privateKey,
			"shortIds":   []any{"abcd"},
		},
	}
	got, err := panelStreamSettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	var panel map[string]any
	if err := json.Unmarshal([]byte(got), &panel); err != nil {
		t.Fatal(err)
	}
	reality := panel["realitySettings"].(map[string]any)
	settings := reality["settings"].(map[string]any)
	if settings["publicKey"] != wantPublicKey {
		t.Fatalf("public key = %v, want %s", settings["publicKey"], wantPublicKey)
	}
}

func TestInvalidCandidateDoesNotReplaceConfig(t *testing.T) {
	m, _, path := testManager(t)
	if err := m.adopt(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	ib := m.inbounds()[0]
	ib.StreamSettings = `{"reject":true}`
	if _, err := m.updateInbound(ib.ID, ib); err == nil {
		t.Fatal("expected validation error")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("invalid candidate replaced live config")
	}
}

func TestInboundTagRenameUpdatesRoutingReferences(t *testing.T) {
	m, _, path := testManager(t)
	root, err := readObject(path)
	if err != nil {
		t.Fatal(err)
	}
	root["outbounds"] = []any{
		map[string]any{"tag": "tw-land-hy2", "protocol": "hysteria"},
		map[string]any{"tag": "direct", "protocol": "freedom"},
	}
	root["routing"] = map[string]any{"rules": []any{
		map[string]any{
			"type":        "field",
			"inboundTag":  []any{"existing"},
			"outboundTag": "direct",
		},
	}}
	b, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.adopt(); err != nil {
		t.Fatal(err)
	}

	ib := m.inbounds()[0]
	ib.Tag = "in-443-tcp"
	if _, err := m.updateInbound(ib.ID, ib); err != nil {
		t.Fatal(err)
	}

	root, err = readObject(path)
	if err != nil {
		t.Fatal(err)
	}
	routing := root["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	rule := rules[0].(map[string]any)
	tags := rule["inboundTag"].([]any)
	if len(tags) != 1 || tags[0] != "in-443-tcp" {
		t.Fatalf("routing inboundTag = %v, want [in-443-tcp]", tags)
	}
	if rule["outboundTag"] != "direct" {
		t.Fatalf("routing outboundTag = %v, want direct", rule["outboundTag"])
	}
}

func TestRewriteInboundTagReferencesPreservesUnrelatedTags(t *testing.T) {
	root := map[string]any{
		"routing": map[string]any{"rules": []any{
			map[string]any{"inboundTag": []any{"old", "keep"}, "outboundTag": "direct"},
		}},
	}
	rewriteInboundTagReferences(root, map[string]string{"old": "new"})
	rules := root["routing"].(map[string]any)["rules"].([]any)
	tags := rules[0].(map[string]any)["inboundTag"].([]any)
	if len(tags) != 2 || tags[0] != "new" || tags[1] != "keep" {
		t.Fatalf("routing inboundTag = %v, want [new keep]", tags)
	}

	rewriteInboundTagReferences(map[string]any{}, map[string]string{"old": "new"})
}

func TestAPIAuthenticationAndIntegrity(t *testing.T) {
	m, cfg, _ := testManager(t)
	if err := m.adopt(); err != nil {
		t.Fatal(err)
	}
	a := newAPIServer(cfg, m)
	unauth := httptest.NewRecorder()
	a.server.Handler.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/panel/api/inbounds/list", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauth.Code)
	}

	form := url.Values{"port": {"8443"}, "protocol": {"vless"}, "tag": {"new"}, "settings": {`{"clients":[]}`}}
	req := httptest.NewRequest(http.MethodPost, "/panel/api/inbounds/add", strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Config-Sha256", strings.Repeat("0", 64))
	badHash := httptest.NewRecorder()
	a.server.Handler.ServeHTTP(badHash, req)
	if badHash.Code != http.StatusBadRequest {
		t.Fatalf("bad hash status = %d", badHash.Code)
	}
}
