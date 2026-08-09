package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxRequestBody = 16 << 20

type apiServer struct {
	cfg     *config
	manager *manager
	server  *http.Server
}

func newAPIServer(cfg *config, manager *manager) *apiServer {
	a := &apiServer{cfg: cfg, manager: manager}
	a.server = &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.auth(http.HandlerFunc(a.route)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return a
}

func (a *apiServer) listenAndServe() error {
	startSystemSampler()
	a.manager.startStatsSampler()
	if a.cfg.TLSCertFile != "" {
		return a.server.ListenAndServeTLS(a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
	}
	log.Print("warning: TLS is disabled; use only behind a trusted private transport")
	return a.server.ListenAndServe()
}

func (a *apiServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(a.cfg.Token) || subtle.ConstantTimeCompare([]byte(provided), []byte(a.cfg.Token)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(envelope{Success: false, Msg: "unauthorized"})
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (a *apiServer) route(w http.ResponseWriter, r *http.Request) {
	log.Printf("api: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	path := strings.TrimPrefix(r.URL.Path, "/")
	if !strings.HasPrefix(path, "panel/api/") {
		a.fail(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if err := verifyBodyHash(r); err != nil {
		a.fail(w, http.StatusBadRequest, err)
		return
	}

	switch {
	case r.Method == http.MethodGet && path == "panel/api/server/status":
		a.ok(w, collectStatus(a.cfg))
	case r.Method == http.MethodGet && path == "panel/api/server/descendants":
		a.ok(w, []any{})
	case r.Method == http.MethodGet && path == "panel/api/server/getWebCertFiles":
		a.ok(w, map[string]string{"webCertFile": a.cfg.TLSCertFile, "webKeyFile": a.cfg.TLSKeyFile})
	case r.Method == http.MethodPost && path == "panel/api/server/restartXrayService":
		a.restart(w)
	case r.Method == http.MethodGet && path == "panel/api/inbounds/list":
		_ = a.manager.refreshStats()
		a.ok(w, a.manager.inbounds())
	case r.Method == http.MethodPost && path == "panel/api/inbounds/add":
		a.addInbound(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/inbounds/update/"):
		a.updateInbound(w, r, strings.TrimPrefix(path, "panel/api/inbounds/update/"))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/inbounds/del/"):
		a.deleteInbound(w, strings.TrimPrefix(path, "panel/api/inbounds/del/"))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/inbounds/setEnable/"):
		a.setEnable(w, r, strings.TrimPrefix(path, "panel/api/inbounds/setEnable/"))
	case r.Method == http.MethodPost && path == "panel/api/inbounds/resetAllTraffics":
		a.result(w, a.manager.resetTraffic("", 0))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/inbounds/") && strings.HasSuffix(path, "/resetTraffic"):
		idText := strings.TrimSuffix(strings.TrimPrefix(path, "panel/api/inbounds/"), "/resetTraffic")
		id, err := strconv.Atoi(idText)
		if err == nil {
			err = a.manager.resetTraffic("", id)
		}
		a.result(w, err)
	case r.Method == http.MethodPost && path == "panel/api/clients/add":
		a.addClient(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/clients/update/"):
		a.updateClient(w, r, strings.TrimPrefix(path, "panel/api/clients/update/"))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/clients/del/"):
		email, _ := url.PathUnescape(strings.TrimPrefix(path, "panel/api/clients/del/"))
		a.result(w, a.manager.deleteClient(email, nil))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "panel/api/clients/resetTraffic/"):
		email, _ := url.PathUnescape(strings.TrimPrefix(path, "panel/api/clients/resetTraffic/"))
		a.result(w, a.manager.resetTraffic(email, 0))
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/detach") && strings.HasPrefix(path, "panel/api/clients/"):
		a.detachClient(w, r, path)
	case r.Method == http.MethodPost && path == "panel/api/clients/onlinesByGuid":
		a.ok(w, a.manager.onlineByGUID())
	case r.Method == http.MethodPost && path == "panel/api/clients/onlines":
		tree := a.manager.onlineByGUID()
		a.ok(w, tree[a.cfg.PanelGUID])
	case r.Method == http.MethodPost && path == "panel/api/clients/lastOnline":
		a.ok(w, a.manager.lastOnline())
	case r.Method == http.MethodGet && path == "panel/api/hosts/list":
		a.ok(w, []any{})
	case path == "panel/api/server/clientIps" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		a.ok(w, []any{})
	case path == "panel/api/clients/clientIpsByGuid" && r.Method == http.MethodPost:
		a.ok(w, map[string]any{})
	case r.Method == http.MethodPost && path == "panel/api/inbounds/pushClientTraffics":
		a.ok(w, nil)
	default:
		a.fail(w, http.StatusNotFound, errors.New("not found"))
	}
}

// isConfigMutation reports whether a panel request path actually changes
// Xray configuration. The panel only signs these with X-Config-Sha256;
// query-style POSTs (onlines, lastOnline, clientIps...) never carry it.
func isConfigMutation(path string) bool {
	p := strings.TrimPrefix(path, "/")
	return strings.HasPrefix(p, "panel/api/inbounds/add") ||
		strings.HasPrefix(p, "panel/api/inbounds/update/") ||
		strings.HasPrefix(p, "panel/api/inbounds/del/") ||
		strings.HasPrefix(p, "panel/api/inbounds/setEnable/") ||
		p == "panel/api/inbounds/resetAllTraffics" ||
		strings.HasSuffix(p, "/resetTraffic") ||
		strings.HasPrefix(p, "panel/api/clients/add") ||
		strings.HasPrefix(p, "panel/api/clients/update/") ||
		strings.HasPrefix(p, "panel/api/clients/del/") ||
		strings.HasPrefix(p, "panel/api/clients/resetTraffic/") ||
		strings.HasSuffix(p, "/detach") ||
		p == "panel/api/server/restartXrayService"
}

func verifyBodyHash(r *http.Request) error {
	want := strings.TrimSpace(r.Header.Get("X-Config-Sha256"))
	if want == "" || r.Body == nil {
		if want == "" && r.Method == http.MethodPost && isConfigMutation(r.URL.Path) {
			log.Printf("warning: config mutation %s without X-Config-Sha256 header", r.URL.Path)
		}
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(want)), []byte(got)) != 1 {
		return errors.New("request body integrity check failed")
	}
	return nil
}

func (a *apiServer) restart(w http.ResponseWriter) {
	for _, svc := range a.cfg.Services {
		if err := runCommand(svc.RestartCommand, 30*time.Second); err != nil {
			a.fail(w, http.StatusOK, fmt.Errorf("restart %s: %w", svc.Name, err))
			return
		}
	}
	a.ok(w, nil)
}

func (a *apiServer) addInbound(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.fail(w, http.StatusBadRequest, err)
		return
	}
	ib, err := inboundFromForm(r.PostForm)
	if err == nil {
		ib, err = a.manager.addInbound(ib)
	}
	if err != nil {
		a.fail(w, http.StatusOK, err)
		return
	}
	a.ok(w, ib)
}

func (a *apiServer) updateInbound(w http.ResponseWriter, r *http.Request, idText string) {
	id, err := strconv.Atoi(idText)
	if err == nil {
		err = r.ParseForm()
	}
	var ib inbound
	if err == nil {
		ib, err = inboundFromForm(r.PostForm)
	}
	if err == nil {
		ib, err = a.manager.updateInbound(id, ib)
	}
	if err != nil {
		a.fail(w, http.StatusOK, err)
		return
	}
	a.ok(w, ib)
}

func (a *apiServer) deleteInbound(w http.ResponseWriter, idText string) {
	id, err := strconv.Atoi(idText)
	if err == nil {
		err = a.manager.deleteInbound(id)
	}
	a.result(w, err)
}

func (a *apiServer) setEnable(w http.ResponseWriter, r *http.Request, idText string) {
	id, err := strconv.Atoi(idText)
	if err == nil {
		err = r.ParseForm()
	}
	if err == nil {
		err = a.manager.setInboundEnable(id, parseBoolDefault(r.Form.Get("enable"), false))
	}
	a.result(w, err)
}

type addClientRequest struct {
	Client     client `json:"client"`
	InboundIDs []int  `json:"inboundIds"`
}

func (a *apiServer) addClient(w http.ResponseWriter, r *http.Request) {
	var req addClientRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err == nil {
		err = a.manager.addClient(req.Client, req.InboundIDs)
	}
	a.result(w, err)
}

func (a *apiServer) updateClient(w http.ResponseWriter, r *http.Request, oldEmailText string) {
	oldEmail, _ := url.PathUnescape(oldEmailText)
	var c client
	err := json.NewDecoder(r.Body).Decode(&c)
	ids, parseErr := parseInboundIDs(r.URL.Query()["inboundIds"])
	if err == nil {
		err = parseErr
	}
	if err == nil {
		err = a.manager.updateClient(oldEmail, c, ids)
	}
	a.result(w, err)
}

func (a *apiServer) detachClient(w http.ResponseWriter, r *http.Request, path string) {
	emailText := strings.TrimSuffix(strings.TrimPrefix(path, "panel/api/clients/"), "/detach")
	email, _ := url.PathUnescape(emailText)
	var req struct {
		InboundIDs []int `json:"inboundIds"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err == nil {
		err = a.manager.deleteClient(email, req.InboundIDs)
	}
	a.result(w, err)
}

func parseInboundIDs(values []string) ([]int, error) {
	var out []int
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			id, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			out = append(out, id)
		}
	}
	return out, nil
}

func (a *apiServer) result(w http.ResponseWriter, err error) {
	if err != nil {
		a.fail(w, http.StatusOK, err)
		return
	}
	a.ok(w, nil)
}

func (a *apiServer) ok(w http.ResponseWriter, obj any) {
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Obj: obj})
}

func (a *apiServer) fail(w http.ResponseWriter, status int, err error) {
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(envelope{Success: false, Msg: err.Error()})
}
