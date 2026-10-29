package main

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestAllowedHostsLoopbackBind(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want []string
	}{
		{"127.0.0.1:8088", []string{"127.0.0.1", "::1", "localhost"}},
		{"127.0.0.2:8088", []string{"127.0.0.1", "127.0.0.2", "::1", "localhost"}},
		{"localhost:8088", []string{"127.0.0.1", "::1", "localhost"}},
		{"LocalHost:8088", []string{"127.0.0.1", "::1", "localhost"}},
		{"[::1]:8088", []string{"127.0.0.1", "::1", "localhost"}},
	} {
		got, err := allowedHosts(tc.addr, "")
		if err != nil {
			t.Fatalf("allowedHosts(%q): %v", tc.addr, err)
		}
		if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, tc.want) {
			t.Errorf("allowedHosts(%q) = %v, want %v", tc.addr, keys, tc.want)
		}
	}
}

// A non-loopback bind is reachable by other machines under names maggie cannot
// guess, so without MAGGIE_ALLOWED_HOSTS it keeps accepting any Host.
func TestAllowedHostsNonLoopbackBindIsOpen(t *testing.T) {
	for _, addr := range []string{":8088", "0.0.0.0:8088", "[::]:8088", "192.168.1.5:8088", "maggie.lan:8088"} {
		got, err := allowedHosts(addr, "")
		if err != nil {
			t.Fatalf("allowedHosts(%q): %v", addr, err)
		}
		if got != nil {
			t.Errorf("allowedHosts(%q) = %v, want nil (no check)", addr, slices.Sorted(maps.Keys(got)))
		}
	}
}

func TestAllowedHostsExtraNames(t *testing.T) {
	for _, tc := range []struct {
		name, addr, extra string
		want              []string
	}{
		{"loopback adds names", "127.0.0.1:8088", "maggie", []string{"127.0.0.1", "::1", "localhost", "maggie"}},
		{"trims, lowercases, drops empties", "127.0.0.1:8088", " Maggie , ,todo.lan,", []string{"127.0.0.1", "::1", "localhost", "maggie", "todo.lan"}},
		{"ports and brackets are ignored", "127.0.0.1:8088", "maggie:8088,[fd00::1]:80,[fd00::2]", []string{"127.0.0.1", "::1", "fd00::1", "fd00::2", "localhost", "maggie"}},
		// Setting the variable on a public bind turns the check on, with the
		// loopback names kept so an in-container probe on localhost still works.
		{"non-loopback enforces", "0.0.0.0:8088", "maggie.example.com", []string{"127.0.0.1", "::1", "localhost", "maggie.example.com"}},
		{"non-loopback with only separators stays open", ":8088", " , ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := allowedHosts(tc.addr, tc.extra)
			if err != nil {
				t.Fatalf("allowedHosts: %v", err)
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("allowedHosts = %v, want nil (no check)", slices.Sorted(maps.Keys(got)))
				}
				return
			}
			if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, tc.want) {
				t.Errorf("allowedHosts = %v, want %v", keys, tc.want)
			}
		})
	}
}

// A malformed entry is a startup error rather than a name that silently never
// matches, the same stance setupLogging takes on a bad MAGGIE_LOG_LEVEL.
func TestAllowedHostsRejectsMalformedNames(t *testing.T) {
	for _, extra := range []string{"http://maggie", "maggie/ui", "*", "*.example.com", "mag gie", "maggie;evil"} {
		if _, err := allowedHosts("127.0.0.1:8088", extra); err == nil {
			t.Errorf("allowedHosts(%q) succeeded, want an error", extra)
		}
	}
}

// serveChain sends one request through handlerChain and reports whether the
// wrapped handler ran.
func serveChain(t *testing.T, allowed map[string]bool, r *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	reached := false
	h := handlerChain(allowed, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, reached
}

func TestHostCheck(t *testing.T) {
	allowed, err := allowedHosts("127.0.0.1:8088", "maggie")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1:8088", true},
		{"localhost:8088", true},
		{"[::1]:8088", true},
		{"localhost", true},
		{"maggie:8088", true},
		{"MAGGIE:9999", true},
		{"evil.example", false},
		{"evil.example:8088", false},
		{"localhost.evil.example:8088", false},
		{"127.0.0.1.nip.io:8088", false},
		{"localhost.:8088", false},
		{"[::1%25lo]:8088", false},
		{"[0:0:0:0:0:0:0:1]:8088", false},
		{"127.0.0.2:8088", false},
		{"", false},
	} {
		for _, p := range []string{"/", "/health", "/api/issues", "/assets/app.js"} {
			r := httptest.NewRequest(http.MethodGet, p, nil)
			r.Host = tc.host
			rec, reached := serveChain(t, allowed, r)
			if reached != tc.ok {
				t.Errorf("Host %q %s: reached handler = %v, want %v", tc.host, p, reached, tc.ok)
			}
			if tc.ok {
				continue
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("Host %q %s: status %d, want 403", tc.host, p, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("Host %q: Content-Type %q, want text/plain", tc.host, ct)
			}
			if !strings.Contains(rec.Body.String(), "host not allowed") {
				t.Errorf("Host %q: body %q", tc.host, rec.Body.String())
			}
			if rec.Header().Get("Content-Security-Policy") != csp {
				t.Errorf("Host %q: rejection is missing the security headers", tc.host)
			}
		}
	}
}

// Without the loopback bind or MAGGIE_ALLOWED_HOSTS, today's behaviour stands.
func TestHostCheckOpenWhenNoAllowlist(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	r.Host = "evil.example:8088"
	if rec, reached := serveChain(t, nil, r); !reached || rec.Code != http.StatusOK {
		t.Errorf("status %d, reached %v; want the request through", rec.Code, reached)
	}
}

// Writes accept any body as JSON, so a cross-site page could otherwise post one
// as a "simple" text/plain request that skips the CORS preflight.
func TestCrossOriginWritesAreRejected(t *testing.T) {
	allowed, err := allowedHosts("127.0.0.1:8088", "maggie")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, host string
		headers            map[string]string
		ok                 bool
	}{
		{"cross-site fetch", http.MethodPost, "127.0.0.1:8088", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://evil.example"}, false},
		{"same-site other port", http.MethodPost, "127.0.0.1:8088", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:3000"}, false},
		{"old browser, foreign origin", http.MethodPost, "127.0.0.1:8088", map[string]string{"Origin": "http://evil.example"}, false},
		{"old browser, opaque origin", http.MethodPost, "127.0.0.1:8088", map[string]string{"Origin": "null"}, false},
		{"old browser, allowed name but other origin", http.MethodPost, "127.0.0.1:8088", map[string]string{"Origin": "http://maggie:8088"}, false},
		{"same-origin fetch", http.MethodPost, "127.0.0.1:8088", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8088"}, true},
		{"old browser, same origin", http.MethodPost, "maggie:8088", map[string]string{"Origin": "http://maggie:8088"}, true},
		{"non-browser client", http.MethodPost, "127.0.0.1:8088", nil, true},
		{"cross-site read", http.MethodGet, "127.0.0.1:8088", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, a := range []map[string]bool{allowed, nil} {
				r := httptest.NewRequest(tc.method, "/api/issue/comment", strings.NewReader(`{}`))
				r.Host = tc.host
				r.Header.Set("Content-Type", "text/plain")
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				rec, reached := serveChain(t, a, r)
				if reached != tc.ok {
					t.Fatalf("allowlist %v: reached handler = %v, want %v (status %d)", a != nil, reached, tc.ok, rec.Code)
				}
				if !tc.ok && rec.Code != http.StatusForbidden {
					t.Errorf("status %d, want 403", rec.Code)
				}
			}
		})
	}
}
