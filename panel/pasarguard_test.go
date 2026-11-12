package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakePG mimics the PasarGuard endpoints regionhop uses.
type fakePG struct {
	core      map[string]any
	coreSaves int
	restarted bool
	hosts     map[int]map[string]any
	nextHost  int
	srv       *httptest.Server
}

func newFakePG(t *testing.T, xray string) *fakePG {
	f := &fakePG{hosts: map[int]map[string]any{}, nextHost: 100}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(xray), &cfg); err != nil {
		t.Fatal(err)
	}
	f.core = map[string]any{"id": 7, "name": "psi", "config": cfg, "exclude_inbound_tags": []string{}, "fallbacks_inbound_tags": nil}
	f.hosts[5] = map[string]any{"id": 5, "remark": "Multi {location}", "address": []string{"1.2.3.4"}, "port": 443,
		"inbound_tag": "in-443", "sni": []string{"a.example"}, "security": "inbound_default", "fingerprint": "chrome",
		"is_disabled": true, "vless_route": nil, "priority": 10}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "key" {
			w.WriteHeader(401)
			w.Write([]byte(`{"detail":"Could not validate credentials"}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/api/core/7" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(f.core)
		case r.URL.Path == "/api/core/7" && r.Method == http.MethodPut:
			var in map[string]any
			if err := json.Unmarshal(body, &in); err != nil {
				t.Errorf("bad core body: %v", err)
			}
			f.restarted = r.URL.Query().Get("restart_nodes") == "true"
			in["id"] = 7
			f.core = in
			f.coreSaves++
			json.NewEncoder(w).Encode(in)
		case r.URL.Path == "/api/host/" && r.Method == http.MethodPost:
			var h map[string]any
			json.Unmarshal(body, &h)
			if _, ok := h["id"]; ok {
				t.Errorf("created host carries an id")
			}
			f.nextHost++
			h["id"] = f.nextHost
			f.hosts[f.nextHost] = h
			json.NewEncoder(w).Encode(h)
		case strings.HasPrefix(r.URL.Path, "/api/host/"):
			id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/host/"))
			h, ok := f.hosts[id]
			if !ok {
				w.WriteHeader(404)
				w.Write([]byte(`{"detail":"Host not found"}`))
				return
			}
			switch r.Method {
			case http.MethodGet:
				json.NewEncoder(w).Encode(h)
			case http.MethodPut:
				var nh map[string]any
				json.Unmarshal(body, &nh)
				nh["id"] = id
				f.hosts[id] = nh
				json.NewEncoder(w).Encode(nh)
			case http.MethodDelete:
				delete(f.hosts, id)
				w.WriteHeader(204)
			}
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"detail":"Not Found"}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePG) rules(t *testing.T) []map[string]any {
	b, _ := json.Marshal(f.core["config"])
	var c struct {
		Routing struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c.Routing.Rules
}

func (f *fakePG) outboundTags(t *testing.T) []string {
	b, _ := json.Marshal(f.core["config"])
	return tags(t, string(b))
}

const pgBaseXray = `{"inbounds":[{"tag":"in-443","port":443,"protocol":"vless"}],
"outbounds":[{"tag":"DIRECT","protocol":"freedom"},{"tag":"BLOCK","protocol":"blackhole"}],
"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"BLOCK"}]}}`

func withPGSettingsFile(t *testing.T) {
	old := pgSettingsFile
	pgSettingsFile = filepath.Join(t.TempDir(), "pasarguard.json")
	t.Cleanup(func() { pgSettingsFile = old })
}

func TestAssignRoutesStable(t *testing.T) {
	r, changed := assignRoutes(nil, []string{"us", "jp"})
	if !changed || r["jp"] != 1 || r["us"] != 2 {
		t.Fatalf("first assignment: %v", r)
	}
	// us removed, de added: jp keeps 1, de gets the lowest free number (2)
	r2, _ := assignRoutes(r, []string{"jp", "de"})
	if r2["jp"] != 1 || r2["de"] != 2 || len(r2) != 2 {
		t.Fatalf("after change: %v", r2)
	}
	r3, changed := assignRoutes(r2, []string{"de", "jp"})
	if changed || r3["jp"] != 1 || r3["de"] != 2 {
		t.Fatalf("no-op reported change or moved routes: %v %v", r3, changed)
	}
}

func TestPGApplyCoreAndHosts(t *testing.T) {
	withPGSettingsFile(t)
	f := newFakePG(t, pgBaseXray)
	s := &pgSettings{Enabled: true, URL: f.srv.URL, APIKey: "key", CoreID: 7, InboundTags: []string{"in-443"}, TemplateHostID: 5}
	list := []Tunnel{{Name: "us", Region: "US", SocksPort: 19000}, {Name: "jp", Region: "JP", SocksPort: 19001}}

	changed, err := pgApply(s, list)
	if err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	if f.coreSaves != 1 || !f.restarted {
		t.Fatalf("core saves=%d restarted=%v", f.coreSaves, f.restarted)
	}
	if got := strings.Join(f.outboundTags(t), ","); got != "DIRECT,BLOCK,regionhop-us,regionhop-jp" && got != "DIRECT,BLOCK,regionhop-jp,regionhop-us" {
		t.Fatalf("outbounds: %s", got)
	}
	rules := f.rules(t)
	if len(rules) != 3 || rules[0]["vlessRoute"] != "1" || rules[0]["outboundTag"] != "regionhop-jp" ||
		rules[1]["vlessRoute"] != "2" || rules[1]["outboundTag"] != "regionhop-us" || rules[2]["outboundTag"] != "BLOCK" {
		t.Fatalf("rules: %v", rules)
	}
	if in, _ := rules[0]["inboundTag"].([]any); len(in) != 1 || in[0] != "in-443" {
		t.Fatalf("inbound tag not set: %v", rules[0])
	}
	// two hosts cloned from the template, besides the template itself
	if len(f.hosts) != 3 {
		t.Fatalf("hosts: %v", f.hosts)
	}
	jp := f.hosts[s.HostIDs["jp"]]
	if jp["vless_route"] != "0001" || jp["inbound_tag"] != "in-443" || jp["is_disabled"] != false ||
		!strings.HasPrefix(jp["remark"].(string), "Multi ") || !strings.HasSuffix(jp["remark"].(string), " jp") {
		t.Fatalf("jp host: %v", jp)
	}
	if f.hosts[5]["is_disabled"] != true {
		t.Fatalf("template host was modified")
	}

	// nothing changed: no write at all
	changed, err = pgApply(s, list)
	if err != nil || changed || f.coreSaves != 1 {
		t.Fatalf("second apply: changed=%v err=%v saves=%d", changed, err, f.coreSaves)
	}

	// remove us: its outbound, rule and host go; jp keeps route 1
	changed, err = pgApply(s, list[1:])
	if err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if got := strings.Join(f.outboundTags(t), ","); got != "DIRECT,BLOCK,regionhop-jp" {
		t.Fatalf("outbounds after remove: %s", got)
	}
	if rules := f.rules(t); len(rules) != 2 || rules[0]["vlessRoute"] != "1" {
		t.Fatalf("rules after remove: %v", rules)
	}
	if len(f.hosts) != 2 || s.HostIDs["us"] != 0 {
		t.Fatalf("hosts after remove: %v %v", f.hosts, s.HostIDs)
	}

	// a host deleted in PasarGuard by hand is created again
	delete(f.hosts, s.HostIDs["jp"])
	if _, err := pgApply(s, list[1:]); err != nil || len(f.hosts) != 2 {
		t.Fatalf("recreate: err=%v hosts=%v", err, f.hosts)
	}
}

func TestPGBadKeyAndMissingCore(t *testing.T) {
	withPGSettingsFile(t)
	f := newFakePG(t, pgBaseXray)
	s := &pgSettings{URL: f.srv.URL, APIKey: "wrong", CoreID: 7}
	if _, err := pgApply(s, nil); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("bad key: %v", err)
	}
	s = &pgSettings{URL: f.srv.URL, APIKey: "key", CoreID: 9}
	if _, err := pgApply(s, nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing core: %v", err)
	}
}

func TestNormalizePGURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://hub.example.com:8000/":          "https://hub.example.com:8000",
		"https://hub.example.com:8000/dashboard": "https://hub.example.com:8000",
		" http://127.0.0.1:8000/api ":            "http://127.0.0.1:8000",
	} {
		if got, err := normalizePGURL(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	if _, err := normalizePGURL("hub.example.com"); err == nil {
		t.Errorf("no scheme accepted")
	}
}

func TestSettingsPageRendersPGCard(t *testing.T) {
	for _, lang := range []string{"en", "fa", "ar", "ru", "zh"} {
		r := httptest.NewRequest("GET", "/settings?lang="+lang, nil)
		w := httptest.NewRecorder()
		data := withLang(r, credsTemplateData(psiphonCreds{}, false, ""))
		data["PG"] = pgView{Enabled: true, URL: "https://hub.example.com:8000", HasKey: true, CoreID: 7, InboundTags: "in-443",
			TemplateHostID: 5, Routes: []pgRouteView{{Name: "jp", Route: 1, Hex: "0001"}}, LastSync: "2026-11-12 10:00"}
		if err := tmpl.ExecuteTemplate(w, "settings.html", data); err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
		body := w.Body.String()
		for _, want := range []string{`id="pg-form"`, `value="https://hub.example.com:8000"`, `name="pg_core"`, `/settings/pasarguard/sync`, `jp = 0001`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", lang, want)
			}
		}
	}
}
