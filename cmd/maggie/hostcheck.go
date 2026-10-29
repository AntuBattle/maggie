package main

import (
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// hostnameRe is the shape of a DNS name: dot-separated labels, no wildcards.
var hostnameRe = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*$`)

// allowedHosts returns the Host header names maggie answers to, or nil when
// any Host is accepted. extra is MAGGIE_ALLOWED_HOSTS.
//
// A loopback bind is only reachable from this machine, so the one way a remote
// page can reach it is DNS rebinding: its own name re-resolved to 127.0.0.1.
// The browser then sends that name as Host, which is what the list rejects.
// A non-loopback bind is reached under names maggie cannot guess (LAN
// hostnames, proxies), so it stays open unless the operator lists them.
func allowedHosts(addr, extra string) (map[string]bool, error) {
	allowed := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	named := false
	for e := range strings.SplitSeq(extra, ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		h := hostname(e)
		if net.ParseIP(h) == nil && !hostnameRe.MatchString(h) {
			return nil, fmt.Errorf("MAGGIE_ALLOWED_HOSTS: %q is not a host name or IP address", e)
		}
		allowed[h] = true
		named = true
	}

	bind := hostname(addr)
	if !isLoopback(bind) {
		if !named {
			return nil, nil
		}
		return allowed, nil
	}
	allowed[bind] = true
	return allowed, nil
}

// hostname reduces a Host header or listen address to its lowercased host,
// dropping any port and the brackets around an IPv6 literal. The port is not
// part of the check: a rebinding page can use any port it likes, and a local
// proxy forwards the Host the browser sent, port included.
func hostname(hostport string) string {
	h := hostport
	if host, port, err := net.SplitHostPort(hostport); err == nil && isPort(port) {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.ToLower(h)
}

func isPort(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)
	return s == "" || err == nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostCheck rejects a request whose Host is not in allowed, before it reaches
// a route; a nil allowed lets every request through. 403 rather than 421: a
// browser may retry a 421 on a fresh connection, and nothing about this answer
// changes on retry.
func hostCheck(allowed map[string]bool, next http.Handler) http.Handler {
	if allowed == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[hostname(r.Host)] {
			slog.Warn("rejected request host", "host", r.Host, "path", r.URL.Path)
			http.Error(w, "forbidden: host not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostList renders allowed for the startup log; "*" means no check.
func hostList(allowed map[string]bool) string {
	if allowed == nil {
		return "*"
	}
	return strings.Join(slices.Sorted(maps.Keys(allowed)), ",")
}
