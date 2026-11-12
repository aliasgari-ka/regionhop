package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PasarGuard integration: regionhop keeps, in one PasarGuard core config,
//
//   - one SOCKS outbound per location ("regionhop-<name>" -> 127.0.0.1:<port>,
//     the same outbound the 3x-ui integration writes), and
//   - one routing rule per location, ruleTag "regionhop-<name>", that sends
//     traffic whose VLESS UUID carries that location's route number
//     (Xray's "vlessRoute": the 3rd group of the UUID) to that outbound.
//
// PasarGuard hosts have a "VLESS route" field that writes this number into the
// UUID of the links it hands out, so one inbound on one port can serve every
// location: each host of that inbound is a location. Optionally regionhop also
// keeps those hosts, cloned from a template host you pick.
//
// Only outbounds/rules with the "regionhop-" tag prefix and hosts regionhop
// created itself (their ids are kept in the settings file) are ever touched.
// The PasarGuard node using that core config must run on this server, since the
// SOCKS ports are loopback-only.
const pgSettingsPath = "/opt/psi-panel/data/pasarguard.json"

type pgSettings struct {
	Enabled        bool           `json:"enabled"`
	URL            string         `json:"url"` // dashboard base, e.g. https://hub.example.com:8000
	APIKey         string         `json:"api_key"`
	CoreID         int            `json:"core_id"`
	InboundTags    []string       `json:"inbound_tags,omitempty"`     // rules apply only to these inbounds (empty: any)
	TemplateHostID int            `json:"template_host_id,omitempty"` // 0: don't manage hosts
	Routes         map[string]int `json:"routes,omitempty"`           // location -> route number (stable)
	HostIDs        map[string]int `json:"host_ids,omitempty"`         // location -> host regionhop created
	LastSync       int64          `json:"last_sync,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
}

var pgMu sync.Mutex

// pgSettingsFile is a variable so tests can point it at a temp dir.
var pgSettingsFile = pgSettingsPath

func loadPG() pgSettings {
	var s pgSettings
	if b, err := os.ReadFile(pgSettingsFile); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func savePG(s pgSettings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := pgSettingsFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, pgSettingsFile)
}

func normalizePGURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("enter the PasarGuard address, like https://hub.example.com:8000")
	}
	u.RawQuery, u.Fragment = "", ""
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, "/dashboard")
	p = strings.TrimSuffix(p, "/api")
	u.Path = p
	return u.String(), nil
}

func parseTagList(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

type pgClient struct {
	s    *pgSettings
	http *http.Client
}

func newPGClient(s *pgSettings) *pgClient {
	tr := &http.Transport{}
	if u, err := url.Parse(s.URL); err == nil {
		h := u.Hostname()
		// a self-signed certificate is only accepted on loopback
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}
	return &pgClient{s: s, http: &http.Client{Timeout: 30 * time.Second, Transport: tr}}
}

// call sends a JSON request to a PasarGuard API path ("/api/...") with the API
// key and decodes a JSON answer into out (when out is not nil).
func (c *pgClient) call(method, path string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(body); err != nil {
			return 0, err
		}
		rd = &buf
	}
	req, err := http.NewRequest(method, c.s.URL+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Api-Key", c.s.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("can't reach PasarGuard: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return resp.StatusCode, fmt.Errorf("PasarGuard refused the API key (HTTP %d): check it, and that it may read and update cores and hosts", resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		var d struct {
			Detail any `json:"detail"`
		}
		if json.Unmarshal(b, &d) == nil && d.Detail != nil {
			if s, ok := d.Detail.(string); ok {
				msg = s
			} else {
				j, _ := json.Marshal(d.Detail)
				msg = string(j)
			}
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return resp.StatusCode, fmt.Errorf("PasarGuard %s %s: HTTP %d %s", method, path, resp.StatusCode, msg)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unexpected answer from PasarGuard for %s", path)
		}
	}
	return resp.StatusCode, nil
}

type pgCore struct {
	ID                   int                        `json:"id"`
	Name                 string                     `json:"name"`
	Config               map[string]json.RawMessage `json:"config"`
	ExcludeInboundTags   []string                   `json:"exclude_inbound_tags"`
	FallbacksInboundTags []string                   `json:"fallbacks_inbound_tags"`
}

func (c *pgClient) getCore() (*pgCore, error) {
	var core pgCore
	if _, err := c.call(http.MethodGet, "/api/core/"+strconv.Itoa(c.s.CoreID), nil, &core); err != nil {
		return nil, err
	}
	if core.Config == nil {
		return nil, fmt.Errorf("core config %d has no Xray config", c.s.CoreID)
	}
	return &core, nil
}

// assignRoutes keeps every known location's route number and gives new ones
// the lowest free number (1..65535; 0 is what an unchanged UUID carries).
func assignRoutes(have map[string]int, names []string) (map[string]int, bool) {
	out := map[string]int{}
	used := map[int]bool{}
	changed := false
	for _, n := range names {
		if r, ok := have[n]; ok && r > 0 && r <= 0xffff && !used[r] {
			out[n] = r
			used[r] = true
		}
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	next := 1
	for _, n := range sorted {
		if _, ok := out[n]; ok {
			continue
		}
		for used[next] {
			next++
		}
		if next > 0xffff {
			break
		}
		out[n] = next
		used[next] = true
		changed = true
	}
	if len(out) != len(have) {
		changed = true
	}
	return out, changed
}

func pgRule(name string, route int, inbounds []string) json.RawMessage {
	r := map[string]any{
		"ruleTag":     xuiTag(name),
		"type":        "field",
		"vlessRoute":  strconv.Itoa(route),
		"outboundTag": xuiTag(name),
	}
	if len(inbounds) > 0 {
		r["inboundTag"] = inbounds
	}
	b, _ := json.Marshal(r)
	return b
}

// mergeRules puts one "regionhop-*" rule per location at the top of the rule
// list (each matches only UUIDs carrying its route number, so it can't catch
// other traffic) and keeps every other rule as it is, in order.
func mergeRules(existing []json.RawMessage, routes map[string]int, inbounds []string) ([]json.RawMessage, bool) {
	names := make([]string, 0, len(routes))
	for n := range routes {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return routes[names[i]] < routes[names[j]] })
	var managed, others []json.RawMessage
	for _, n := range names {
		managed = append(managed, pgRule(n, routes[n], inbounds))
	}
	for _, raw := range existing {
		var r struct {
			RuleTag string `json:"ruleTag"`
		}
		json.Unmarshal(raw, &r)
		if !strings.HasPrefix(r.RuleTag, xuiTagPrefix) {
			others = append(others, raw)
		}
	}
	out := append(managed, others...)
	changed := len(out) != len(existing)
	for i := 0; !changed && i < len(out); i++ {
		changed = !jsonEqual(out[i], existing[i])
	}
	return out, changed
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return bytes.Equal(ja, jb)
}

// pgApplyCore brings the core config's outbounds and rules in line with the
// locations. It writes only when something differs, since saving restarts the
// Xray of every node using that core config.
func (c *pgClient) applyCore(ports map[string]int, routes map[string]int) (bool, error) {
	core, err := c.getCore()
	if err != nil {
		return false, err
	}
	cfg := core.Config
	var outs []json.RawMessage
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return false, fmt.Errorf("unexpected outbounds format in core config %d", core.ID)
		}
	}
	mergedOuts, outChanged := mergeOutbounds(outs, ports)

	routing := map[string]json.RawMessage{}
	if raw, ok := cfg["routing"]; ok {
		if err := json.Unmarshal(raw, &routing); err != nil {
			return false, fmt.Errorf("unexpected routing format in core config %d", core.ID)
		}
	}
	var rules []json.RawMessage
	if raw, ok := routing["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return false, fmt.Errorf("unexpected routing rules format in core config %d", core.ID)
		}
	}
	mergedRules, ruleChanged := mergeRules(rules, routes, c.s.InboundTags)
	if !outChanged && !ruleChanged {
		return false, nil
	}
	cfg["outbounds"], _ = json.Marshal(mergedOuts)
	routing["rules"], _ = json.Marshal(mergedRules)
	cfg["routing"], _ = json.Marshal(routing)

	body := map[string]any{
		"name":                   core.Name,
		"config":                 cfg,
		"exclude_inbound_tags":   nonNil(core.ExcludeInboundTags),
		"fallbacks_inbound_tags": nonNil(core.FallbacksInboundTags),
	}
	if _, err := c.call(http.MethodPut, "/api/core/"+strconv.Itoa(core.ID)+"?restart_nodes=true", body, nil); err != nil {
		return false, err
	}
	return true, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// hostFor builds a location's host from the template: same inbound, address,
// security and so on, with the location's remark and VLESS route.
func hostFor(tpl map[string]json.RawMessage, name, region string, route, idx int) map[string]json.RawMessage {
	h := make(map[string]json.RawMessage, len(tpl))
	for k, v := range tpl {
		h[k] = v
	}
	delete(h, "id")
	var remark string
	json.Unmarshal(tpl["remark"], &remark)
	label := strings.TrimSpace(countryFlag(region) + " " + name)
	if strings.Contains(remark, "{location}") {
		remark = strings.ReplaceAll(remark, "{location}", label)
	} else {
		remark = strings.TrimSpace(remark + " " + label)
	}
	h["remark"], _ = json.Marshal(remark)
	h["vless_route"], _ = json.Marshal(fmt.Sprintf("%04x", route))
	h["is_disabled"] = json.RawMessage("false")
	var prio int
	json.Unmarshal(tpl["priority"], &prio)
	h["priority"], _ = json.Marshal(prio + idx + 1)
	return h
}

func hostDiffers(want, have map[string]json.RawMessage) bool {
	for _, k := range []string{"remark", "vless_route", "inbound_tag", "address", "port", "sni", "security", "fingerprint", "is_disabled"} {
		if !jsonEqual(want[k], have[k]) {
			return true
		}
	}
	return false
}

// applyHosts keeps one host per location, cloned from the template host. Hosts
// of removed locations are deleted; nothing else is touched.
func (c *pgClient) applyHosts(list []Tunnel, routes map[string]int) (bool, error) {
	if c.s.TemplateHostID <= 0 {
		return false, nil
	}
	var tpl map[string]json.RawMessage
	if _, err := c.call(http.MethodGet, "/api/host/"+strconv.Itoa(c.s.TemplateHostID), nil, &tpl); err != nil {
		return false, fmt.Errorf("template host %d: %v", c.s.TemplateHostID, err)
	}
	if c.s.HostIDs == nil {
		c.s.HostIDs = map[string]int{}
	}
	changed := false
	sorted := append([]Tunnel(nil), list...)
	sort.Slice(sorted, func(i, j int) bool { return routes[sorted[i].Name] < routes[sorted[j].Name] })
	keep := map[string]bool{}
	for i, t := range sorted {
		route, ok := routes[t.Name]
		if !ok {
			continue
		}
		keep[t.Name] = true
		want := hostFor(tpl, t.Name, t.Region, route, i)
		if id := c.s.HostIDs[t.Name]; id > 0 && id != c.s.TemplateHostID {
			var have map[string]json.RawMessage
			code, err := c.call(http.MethodGet, "/api/host/"+strconv.Itoa(id), nil, &have)
			if err == nil {
				if hostDiffers(want, have) {
					if _, err := c.call(http.MethodPut, "/api/host/"+strconv.Itoa(id), want, nil); err != nil {
						return changed, err
					}
					changed = true
				}
				continue
			}
			if code != http.StatusNotFound {
				return changed, err
			}
			// deleted in PasarGuard: create it again below
		}
		var created struct {
			ID int `json:"id"`
		}
		if _, err := c.call(http.MethodPost, "/api/host/", want, &created); err != nil {
			return changed, err
		}
		c.s.HostIDs[t.Name] = created.ID
		changed = true
	}
	for name, id := range c.s.HostIDs {
		if keep[name] {
			continue
		}
		if id > 0 && id != c.s.TemplateHostID {
			if code, err := c.call(http.MethodDelete, "/api/host/"+strconv.Itoa(id), nil, nil); err != nil && code != http.StatusNotFound {
				return changed, err
			}
		}
		delete(c.s.HostIDs, name)
		changed = true
	}
	return changed, nil
}

// pgSync brings PasarGuard in line with the current locations and records the
// result in the settings file. A no-op when the integration is off.
func pgSync() (changed bool, err error) {
	pgMu.Lock()
	defer pgMu.Unlock()
	s := loadPG()
	if !s.Enabled {
		return false, nil
	}
	defer func() {
		s.LastSync = time.Now().Unix()
		s.LastError = ""
		if err != nil {
			s.LastError = err.Error()
		}
		savePG(s)
	}()
	list, lerr := loadRegistry(registryPath)
	if lerr != nil {
		return false, lerr
	}
	return pgApply(&s, list)
}

func pgApply(s *pgSettings, list []Tunnel) (bool, error) {
	if s.CoreID <= 0 {
		return false, fmt.Errorf("enter the id of the PasarGuard core config to use")
	}
	ports := make(map[string]int, len(list))
	names := make([]string, 0, len(list))
	for _, t := range list {
		ports[t.Name] = t.SocksPort
		names = append(names, t.Name)
	}
	routes, _ := assignRoutes(s.Routes, names)
	s.Routes = routes
	c := newPGClient(s)
	coreChanged, err := c.applyCore(ports, routes)
	if err != nil {
		return false, err
	}
	hostsChanged, err := c.applyHosts(list, routes)
	return coreChanged || hostsChanged, err
}

func pgSyncAsync() {
	go func() {
		if _, err := pgSync(); err != nil {
			log.Printf("PasarGuard sync: %v", err)
		}
	}()
}
