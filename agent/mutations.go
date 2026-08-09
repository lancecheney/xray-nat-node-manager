package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func inboundFromForm(form url.Values) (inbound, error) {
	port, err := strconv.Atoi(form.Get("port"))
	if err != nil || port < 0 || port > 65535 {
		return inbound{}, errors.New("invalid port")
	}
	protocol := form.Get("protocol")
	if protocol == "" {
		return inbound{}, errors.New("protocol is required")
	}
	if form.Get("tag") == "" {
		return inbound{}, errors.New("tag is required")
	}
	for _, key := range []string{"settings", "streamSettings", "sniffing"} {
		value := form.Get(key)
		if value == "" {
			value = "{}"
		}
		var v any
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return inbound{}, fmt.Errorf("invalid %s: %w", key, err)
		}
	}
	return inbound{
		Total:             parseInt64(form.Get("total")),
		Remark:            form.Get("remark"),
		SubSortIndex:      int(parseInt64Default(form.Get("subSortIndex"), 1)),
		Enable:            parseBoolDefault(form.Get("enable"), true),
		ExpiryTime:        parseInt64(form.Get("expiryTime")),
		TrafficReset:      form.Get("trafficReset"),
		TrafficResetDay:   int(parseInt64(form.Get("trafficResetDay"))),
		Listen:            form.Get("listen"),
		Port:              port,
		Protocol:          protocol,
		Settings:          defaultJSON(form.Get("settings")),
		StreamSettings:    defaultJSON(form.Get("streamSettings")),
		Tag:               form.Get("tag"),
		Sniffing:          defaultJSON(form.Get("sniffing")),
		ShareAddrStrategy: defaultString(form.Get("shareAddrStrategy"), "node"),
		ShareAddr:         form.Get("shareAddr"),
	}, nil
}

func defaultJSON(v string) string {
	if strings.TrimSpace(v) == "" {
		return "{}"
	}
	return v
}

func parseInt64(v string) int64 {
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func parseInt64Default(v string, fallback int64) int64 {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return parseInt64(v)
}

func parseBoolDefault(v string, fallback bool) bool {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func (m *manager) addInbound(ib inbound) (inbound, error) {
	var created inbound
	err := m.mutate(func(next *state) (map[string]bool, error) {
		for _, rec := range next.Inbounds {
			if rec.Inbound.Tag == ib.Tag {
				return nil, fmt.Errorf("inbound tag %q already exists", ib.Tag)
			}
		}
		service := ""
		for _, svc := range m.cfg.Services {
			if svc.Default {
				service = svc.Name
				break
			}
		}
		ib.ID = next.NextID
		next.NextID++
		next.Inbounds = append(next.Inbounds, inboundRecord{Inbound: ib, Service: service})
		next.KnownTags[service] = appendUnique(next.KnownTags[service], ib.Tag)
		created = ib
		return map[string]bool{service: true}, nil
	})
	return created, err
}

func (m *manager) updateInbound(id int, updated inbound) (inbound, error) {
	var result inbound
	err := m.mutate(func(next *state) (map[string]bool, error) {
		idx := recordIndex(next, id)
		if idx < 0 {
			return nil, errors.New("inbound not found")
		}
		for i, rec := range next.Inbounds {
			if i != idx && rec.Inbound.Tag == updated.Tag {
				return nil, fmt.Errorf("inbound tag %q already exists", updated.Tag)
			}
		}
		old := next.Inbounds[idx]
		updated.ID = id
		updated.Up = old.Inbound.Up
		updated.Down = old.Inbound.Down
		updated.ClientStats = old.Inbound.ClientStats
		updated.LastTrafficResetTime = old.Inbound.LastTrafficResetTime
		next.Inbounds[idx].Inbound = updated
		next.KnownTags[old.Service] = appendUnique(next.KnownTags[old.Service], old.Inbound.Tag)
		next.KnownTags[old.Service] = appendUnique(next.KnownTags[old.Service], updated.Tag)
		if old.Inbound.Tag != updated.Tag {
			if next.TagRenames == nil {
				next.TagRenames = map[string]map[string]string{}
			}
			if next.TagRenames[old.Service] == nil {
				next.TagRenames[old.Service] = map[string]string{}
			}
			next.TagRenames[old.Service][old.Inbound.Tag] = updated.Tag
		}
		result = updated
		return map[string]bool{old.Service: true}, nil
	})
	return result, err
}

func (m *manager) deleteInbound(id int) error {
	return m.mutate(func(next *state) (map[string]bool, error) {
		idx := recordIndex(next, id)
		if idx < 0 {
			return map[string]bool{}, nil
		}
		rec := next.Inbounds[idx]
		next.KnownTags[rec.Service] = appendUnique(next.KnownTags[rec.Service], rec.Inbound.Tag)
		next.Inbounds = append(next.Inbounds[:idx], next.Inbounds[idx+1:]...)
		return map[string]bool{rec.Service: true}, nil
	})
}

func (m *manager) setInboundEnable(id int, enabled bool) error {
	return m.mutate(func(next *state) (map[string]bool, error) {
		idx := recordIndex(next, id)
		if idx < 0 {
			return nil, errors.New("inbound not found")
		}
		next.Inbounds[idx].Inbound.Enable = enabled
		return map[string]bool{next.Inbounds[idx].Service: true}, nil
	})
}

func recordIndex(st *state, id int) int {
	for i := range st.Inbounds {
		if st.Inbounds[i].Inbound.ID == id {
			return i
		}
	}
	return -1
}

func settingsClients(ib *inbound) ([]map[string]any, map[string]any, error) {
	var settings map[string]any
	if err := json.Unmarshal([]byte(defaultJSON(ib.Settings)), &settings); err != nil {
		return nil, nil, err
	}
	rawItems, _ := settings["clients"].([]any)
	items := make([]map[string]any, 0, len(rawItems))
	for _, raw := range rawItems {
		if item, ok := raw.(map[string]any); ok {
			items = append(items, item)
		}
	}
	return items, settings, nil
}

func saveSettingsClients(ib *inbound, settings map[string]any, clients []map[string]any) {
	items := make([]any, len(clients))
	for i := range clients {
		items[i] = clients[i]
	}
	settings["clients"] = items
	ib.Settings = rawJSON(settings)
}

func clientMap(c client) map[string]any {
	b, _ := json.Marshal(c)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func clientEmail(c map[string]any) string {
	email, _ := c["email"].(string)
	return email
}

func (m *manager) addClient(c client, inboundIDs []int) error {
	if c.Email == "" || len(inboundIDs) == 0 {
		return errors.New("client email and inboundIds are required")
	}
	wanted := intSet(inboundIDs)
	return m.mutate(func(next *state) (map[string]bool, error) {
		affected := map[string]bool{}
		found := 0
		for i := range next.Inbounds {
			ib := &next.Inbounds[i].Inbound
			if !wanted[ib.ID] {
				continue
			}
			found++
			clients, settings, err := settingsClients(ib)
			if err != nil {
				return nil, err
			}
			for _, existing := range clients {
				if strings.EqualFold(clientEmail(existing), c.Email) {
					return nil, fmt.Errorf("client %q already exists", c.Email)
				}
			}
			clients = append(clients, clientMap(c))
			saveSettingsClients(ib, settings, clients)
			affected[next.Inbounds[i].Service] = true
		}
		if found != len(wanted) {
			return nil, errors.New("one or more inbounds not found")
		}
		return affected, nil
	})
}

func (m *manager) updateClient(oldEmail string, updated client, inboundIDs []int) error {
	if oldEmail == "" || updated.Email == "" {
		return errors.New("client email is required")
	}
	wanted := intSet(inboundIDs)
	return m.mutate(func(next *state) (map[string]bool, error) {
		affected := map[string]bool{}
		found := false
		for i := range next.Inbounds {
			ib := &next.Inbounds[i].Inbound
			if len(wanted) > 0 && !wanted[ib.ID] {
				continue
			}
			clients, settings, err := settingsClients(ib)
			if err != nil {
				return nil, err
			}
			changed := false
			for j, existing := range clients {
				if strings.EqualFold(clientEmail(existing), oldEmail) {
					clients[j] = clientMap(updated)
					changed, found = true, true
				}
			}
			if changed {
				saveSettingsClients(ib, settings, clients)
				affected[next.Inbounds[i].Service] = true
			}
		}
		if !found {
			return nil, errors.New("client not found")
		}
		return affected, nil
	})
}

func (m *manager) deleteClient(email string, inboundIDs []int) error {
	if email == "" {
		return errors.New("client email is required")
	}
	wanted := intSet(inboundIDs)
	return m.mutate(func(next *state) (map[string]bool, error) {
		affected := map[string]bool{}
		for i := range next.Inbounds {
			ib := &next.Inbounds[i].Inbound
			if len(wanted) > 0 && !wanted[ib.ID] {
				continue
			}
			clients, settings, err := settingsClients(ib)
			if err != nil {
				return nil, err
			}
			kept := clients[:0]
			for _, existing := range clients {
				if !strings.EqualFold(clientEmail(existing), email) {
					kept = append(kept, existing)
				}
			}
			if len(kept) != len(clients) {
				saveSettingsClients(ib, settings, kept)
				affected[next.Inbounds[i].Service] = true
			}
		}
		return affected, nil
	})
}

func (m *manager) inbounds() []inbound {
	st := m.snapshot()
	out := make([]inbound, 0, len(st.Inbounds))
	for _, rec := range st.Inbounds {
		out = append(out, rec.Inbound)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func intSet(items []int) map[int]bool {
	out := make(map[int]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}
