package main

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type pgRouteView struct {
	Name  string
	Route int
	Hex   string
}

type pgView struct {
	Enabled        bool
	URL            string
	HasKey         bool
	CoreID         int
	InboundTags    string
	TemplateHostID int
	Routes         []pgRouteView
	LastSync       string
	LastError      string
}

func pgTemplateData() pgView {
	s := loadPG()
	v := pgView{
		Enabled: s.Enabled, URL: s.URL, HasKey: s.APIKey != "", CoreID: s.CoreID,
		InboundTags: strings.Join(s.InboundTags, ", "), TemplateHostID: s.TemplateHostID, LastError: s.LastError,
	}
	for n, r := range s.Routes {
		v.Routes = append(v.Routes, pgRouteView{Name: n, Route: r, Hex: fmt.Sprintf("%04x", r)})
	}
	sort.Slice(v.Routes, func(i, j int) bool { return v.Routes[i].Route < v.Routes[j].Route })
	if s.LastSync > 0 {
		v.LastSync = time.Unix(s.LastSync, 0).Format("2006-01-02 15:04")
	}
	return v
}

// pgFormSettings builds settings from the form; a blank API key keeps the
// saved one, so the secret never has to be sent back to the page.
func pgFormSettings(r *http.Request) (pgSettings, error) {
	s := loadPG()
	s.Enabled = r.FormValue("pg_enabled") != ""
	base, err := normalizePGURL(r.FormValue("pg_url"))
	if err != nil {
		return s, err
	}
	s.URL = base
	if k := strings.TrimSpace(r.FormValue("pg_key")); k != "" {
		s.APIKey = k
	}
	id, err := strconv.Atoi(strings.TrimSpace(r.FormValue("pg_core")))
	if err != nil || id <= 0 {
		return s, errString("enter the id of the PasarGuard core config to use")
	}
	s.CoreID = id
	s.InboundTags = parseTagList(r.FormValue("pg_inbounds"))
	s.TemplateHostID = 0
	if raw := strings.TrimSpace(r.FormValue("pg_host")); raw != "" {
		h, err := strconv.Atoi(raw)
		if err != nil || h < 0 {
			return s, errString("the template host id must be a number")
		}
		s.TemplateHostID = h
	}
	return s, nil
}

func (a *app) handlePG(w http.ResponseWriter, r *http.Request) {
	setLangCookie(w, r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, urlFor("/settings"), http.StatusSeeOther)
		return
	}
	limitBody(w, r, 64<<10)
	var errMsg string
	s, err := pgFormSettings(r)
	switch {
	case err != nil && r.FormValue("pg_enabled") == "":
		s = loadPG()
		s.Enabled = false
		err = nil
		fallthrough
	case err == nil:
		if s.Enabled && s.APIKey == "" {
			err = errString("paste an API key from PasarGuard")
		}
		if err == nil {
			pgMu.Lock()
			err = savePG(s)
			pgMu.Unlock()
		}
		if err == nil && s.Enabled {
			if _, serr := pgSync(); serr != nil {
				errMsg = serr.Error()
			}
		}
	}
	data := credsTemplateData(a.creds, false, "")
	if err != nil {
		data["PGError"] = err.Error()
	} else if errMsg != "" {
		data["PGError"] = errMsg
	} else {
		data["PGSaved"] = true
	}
	data["PG"] = pgTemplateData()
	tmpl.ExecuteTemplate(w, "settings.html", withLang(r, data))
}

func (a *app) handlePGTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	limitBody(w, r, 64<<10)
	s, err := pgFormSettings(r)
	if err == nil && s.APIKey == "" {
		err = errString("paste an API key from PasarGuard")
	}
	if err == nil {
		_, err = newPGClient(&s).getCore()
	}
	if err == nil && s.TemplateHostID > 0 {
		if _, herr := newPGClient(&s).call(http.MethodGet, "/api/host/"+strconv.Itoa(s.TemplateHostID), nil, nil); herr != nil {
			err = fmt.Errorf("template host %d: %v", s.TemplateHostID, herr)
		}
	}
	if err != nil {
		writeJSON(w, xuiResult{Error: err.Error()})
		return
	}
	writeJSON(w, xuiResult{OK: true})
}

func (a *app) handlePGSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	changed, err := pgSync()
	if err != nil {
		writeJSON(w, xuiResult{Error: err.Error()})
		return
	}
	writeJSON(w, xuiResult{OK: true, Changed: changed})
}

// syncIntegrationsAsync is what add/remove/startup call.
func syncIntegrationsAsync() {
	xuiSyncAsync()
	pgSyncAsync()
}
