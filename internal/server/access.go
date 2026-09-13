package server

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) accessAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		jsonError(w, "method not allowed", 405)
		return
	}
	kind := strings.TrimPrefix(r.URL.Path, "/api/v1/access/")
	if kind != "dns" && kind != "web" {
		http.NotFound(w, r)
		return
	}
	before := uint64(0)
	if value := r.URL.Query().Get("before"); value != "" {
		var err error
		before, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			jsonError(w, "invalid before cursor", 400)
			return
		}
	}
	count := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		var err error
		count, err = strconv.Atoi(value)
		if err != nil || count < 1 || count > 500 {
			jsonError(w, "limit must be between 1 and 500", 400)
			return
		}
	}
	if len(r.URL.Query().Get("q")) > 512 {
		jsonError(w, "query too long", 400)
		return
	}
	jsonOut(w, s.Engine.AccessLog.Query(kind, r.URL.Query().Get("q"), before, count))
}
