package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// These tests cover the parts of verify that do not need an nginx binary:
// reading the URL file, rewriting configs into scratch copies, and mapping
// results back. Running real nginx is exercised by `nginxviz -verify`.

func TestListenPortOf(t *testing.T) {
	cases := []struct {
		src  string
		port int
		ok   bool
	}{
		{"listen 80;", 80, true},
		{"listen 8080 default_server;", 8080, true},
		{"listen 127.0.0.1:8081;", 8081, true},
		{"listen *:8000;", 8000, true},
		{"listen [::]:443 ssl;", 443, true},
		{"listen localhost;", 80, true},
		{"listen [::1];", 80, true},
		{"listen unix:/run/nginx.sock;", 0, false},
	}
	for _, c := range cases {
		p, ok := listenPortOf(parseStr(t, c.src)[0])
		if p != c.port || ok != c.ok {
			t.Errorf("%s -> %d, %v; want %d, %v", c.src, p, ok, c.port, c.ok)
		}
	}
}

func TestHasArg(t *testing.T) {
	d := parseStr(t, "listen 443 ssl default_server;")[0]
	if !hasArg(d, "ssl") || !hasArg(d, "default_server") {
		t.Error("flags after the address not found")
	}
	if hasArg(d, "443") {
		t.Error("the address itself must not count as a flag")
	}
	if hasArg(&Directive{Name: "listen"}, "ssl") {
		t.Error("directive without arguments reported a flag")
	}
}

func TestDropDirective(t *testing.T) {
	for _, n := range []string{"user", "pid", "error_log", "access_log", "ssl_certificate", "ssl_client_certificate",
		"proxy_ssl_verify", "proxy_cache", "proxy_cache_path", "client_body_temp_path", "stream"} {
		if !dropDirective(n) {
			t.Errorf("%s should be dropped from scratch configs", n)
		}
	}
	for _, n := range []string{"listen", "server_name", "proxy_pass", "proxy_set_header", "root", "return", "location", "upstream"} {
		if dropDirective(n) {
			t.Errorf("%s must be kept in scratch configs", n)
		}
	}
}

func TestQuoteArg(t *testing.T) {
	cases := []struct {
		in     string
		quoted bool
		want   string
	}{
		{"plain", false, "plain"},
		{"plain", true, `"plain"`},
		{"", false, `""`},
		{"two words", false, `"two words"`},
		{"a;b", false, `"a;b"`},
		{"a{2}", false, `"a{2}"`},
		{`say "hi"`, true, `"say \"hi\""`},
		{`\.php$`, false, `\.php$`},
		{`\.php$`, true, `"\\.php$"`},
		{"#notcomment", false, `"#notcomment"`},
	}
	for _, c := range cases {
		if got := quoteArg(c.in, c.quoted); got != c.want {
			t.Errorf("quoteArg(%q, %v) = %s, want %s", c.in, c.quoted, got, c.want)
		}
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	for _, path := range []string{"examples/edge/nginx.conf", "examples/app/nginx.conf", "examples/api/nginx.conf"} {
		var warns []string
		orig, err := ParseFile(path, &warns)
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		serialize(&sb, orig, 0)
		again := parseStr(t, sb.String())
		if !sameTree(orig, again) {
			t.Errorf("%s: serialize + parse changed the tree:\n%s", path, sb.String())
		}
	}
	tricky := `
return 200 "say \"hi\"; ok";
location ~ "^/a{2,3}/\d+$" { set $x ''; }
map $a $b { default 0; "~*(bot|spider)" 1; }
content_by_lua_block { ngx.say(1) }
`
	orig := parseStr(t, tricky)
	var sb strings.Builder
	serialize(&sb, orig, 0)
	if !sameTree(orig, parseStr(t, sb.String())) {
		t.Errorf("tricky quoting did not survive a round trip:\n%s", sb.String())
	}
}

func TestReadCases(t *testing.T) {
	dir := writeFiles(t, map[string]string{"urls.txt": `# comment

https://example.com/a?x=1
post http://example.com/b | User-Agent: Googlebot | Cookie: a=b | notaheader
example.com/c
`})
	cases, err := readCases(filepath.Join(dir, "urls.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := []*VCase{
		{Method: "GET", URL: "https://example.com/a?x=1", Headers: []string{}},
		{Method: "POST", URL: "http://example.com/b", Headers: []string{"User-Agent: Googlebot", "Cookie: a=b"}},
		{Method: "GET", URL: "http://example.com/c", Headers: []string{}},
	}
	if !reflect.DeepEqual(cases, want) {
		for _, c := range cases {
			t.Logf("got %+v", *c)
		}
		t.Error("cases differ from expected")
	}
}

func TestReadCasesErrors(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"empty.txt": "# only a comment\n\n",
		"bad.txt":   "GET http://example.com/ extra\n",
	})
	if _, err := readCases(filepath.Join(dir, "empty.txt")); err == nil || !strings.Contains(err.Error(), "no URLs") {
		t.Errorf("empty file: err = %v", err)
	}
	if _, err := readCases(filepath.Join(dir, "bad.txt")); err == nil || !strings.Contains(err.Error(), "cannot parse line") {
		t.Errorf("three fields: err = %v", err)
	}
	if _, err := readCases(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("missing file: no error")
	}
}

func TestExampleURLFileParses(t *testing.T) {
	cases, err := readCases("examples/urls.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 13 {
		t.Errorf("examples/urls.txt has %d requests, want 13", len(cases))
	}
}

// newScratch builds the state RunVerify sets up before rewriting configs,
// with fixed fake ports instead of real listeners.
func newScratch(t *testing.T, b *Bundle, ports ...map[int]int) *scratch {
	t.Helper()
	s := &scratch{b: b, dir: t.TempDir(), stubs: map[string]int{}, notes: map[string]bool{}, closed: 1,
		certFile: "/scratch/cert.pem", keyFile: "/scratch/key.pem"}
	for i, hop := range b.Hops {
		h := &shop{hop: hop, ports: ports[i], ssl: map[int]bool{}, ups: upstreams(hop.Tree),
			dir: filepath.Join(s.dir, "hop"+strconv.Itoa(i))}
		for _, sv := range serverBlocks(hop.Tree) {
			for _, l := range find(sv.Block, "listen") {
				if p, ok := listenPortOf(l); ok && hasArg(l, "ssl") {
					h.ssl[p] = true
				}
			}
		}
		s.hops = append(s.hops, h)
	}
	t.Cleanup(func() {
		for _, l := range s.lns {
			l.Close()
		}
	})
	return s
}

// dirs returns every directive called name anywhere in the tree.
func dirs(ds []*Directive, name string) []*Directive {
	var out []*Directive
	for _, d := range ds {
		if d.Name == name {
			out = append(out, d)
		}
		out = append(out, dirs(d.Block, name)...)
	}
	return out
}

func argLines(ds []*Directive) []string {
	var out []string
	for _, d := range ds {
		out = append(out, strings.Join(d.Args, " "))
	}
	return out
}

func buildScratchConf(t *testing.T, s *scratch, hop int) []*Directive {
	t.Helper()
	conf, err := s.buildConf(s.hops[hop])
	if err != nil {
		t.Fatal(err)
	}
	return parseStr(t, conf) // the scratch config must itself be parseable
}

func TestBuildConfExampleEdge(t *testing.T) {
	b := exampleBundle(t)
	s := newScratch(t, b, map[int]int{80: 41080, 443: 41443}, map[int]int{8080: 42080}, map[int]int{9000: 43000})
	tree := buildScratchConf(t, s, 0)

	// Nothing may listen on, or connect to, anything but 127.0.0.1.
	if got, want := argLines(dirs(tree, "listen")), []string{"127.0.0.1:41080 default_server", "127.0.0.1:41443 ssl"}; !reflect.DeepEqual(got, want) {
		t.Errorf("listen = %q, want %q", got, want)
	}
	var upstreamServers []string
	for _, u := range dirs(tree, "upstream") {
		upstreamServers = append(upstreamServers, argLines(find(u.Block, "server"))...)
	}
	// 10.0.0.5:8080 and 10.0.0.6:8080 are both registered for hop "app".
	if want := []string{"127.0.0.1:42080", "127.0.0.1:42080 backup"}; !reflect.DeepEqual(upstreamServers, want) {
		t.Errorf("upstream servers = %q, want %q", upstreamServers, want)
	}
	// proxy_pass to a named upstream keeps the name (and any URI part).
	if got, want := argLines(dirs(tree, "proxy_pass")), []string{"http://app_pool", "http://app_pool/", "http://app_pool"}; !reflect.DeepEqual(got, want) {
		t.Errorf("proxy_pass = %q, want %q", got, want)
	}
	// Run-time settings point into the scratch directory.
	hopDir := s.hops[0].dir
	for name, want := range map[string]string{
		"daemon":              "off",
		"master_process":      "off",
		"pid":                 filepath.Join(hopDir, "nginx.pid"),
		"error_log":           filepath.Join(hopDir, "error.log") + " debug",
		"access_log":          "off",
		"ssl_certificate":     "/scratch/cert.pem",
		"ssl_certificate_key": "/scratch/key.pem",
	} {
		if got := argLines(dirs(tree, name)); !reflect.DeepEqual(got, []string{want}) {
			t.Errorf("%s = %q, want exactly %q", name, got, want)
		}
	}
	// The original events block is kept, not duplicated.
	if n := len(find(tree, "events")); n != 1 {
		t.Errorf("%d events blocks, want 1", n)
	}
	// Data blocks are copied untouched.
	m := dirs(tree, "map")
	if len(m) != 1 || !reflect.DeepEqual(argLines(m[0].Block), []string{"0", "1"}) {
		t.Errorf("map block altered: %v", m)
	}
	// Existing Host headers are left alone; no extra one is injected because
	// every proxying location targets a named upstream.
	if got := len(dirs(tree, "proxy_set_header")); got != 6 {
		t.Errorf("%d proxy_set_header directives, want the original 6", got)
	}
}

func TestBuildConfExampleAppAndApi(t *testing.T) {
	b := exampleBundle(t)
	s := newScratch(t, b, map[int]int{80: 41080, 443: 41443}, map[int]int{8080: 42080}, map[int]int{9000: 43000})

	app := buildScratchConf(t, s, 1)
	if got, want := argLines(dirs(app, "listen")), []string{"127.0.0.1:42080", "127.0.0.1:42080"}; !reflect.DeepEqual(got, want) {
		t.Errorf("app listen = %q, want %q", got, want)
	}
	// app has no events block of its own, and no TLS listener.
	if n := len(find(app, "events")); n != 1 {
		t.Errorf("%d events blocks in app scratch config, want 1 (added)", n)
	}
	if n := len(dirs(app, "ssl_certificate")); n != 0 {
		t.Error("ssl_certificate added to a hop without TLS listeners")
	}
	// api.internal:9000 is hop "api".
	up := dirs(app, "upstream")
	if got := argLines(find(up[0].Block, "server")); !reflect.DeepEqual(got, []string{"127.0.0.1:43000"}) {
		t.Errorf("api_backend servers = %q", got)
	}
	// 127.0.0.1:3000 has no config: it becomes a local stub, and the Host
	// header nginx would have sent is pinned so the stub sees the original.
	stub, ok := s.stubs["127.0.0.1:3000"]
	if !ok {
		t.Fatalf("no stub for 127.0.0.1:3000; stubs = %v", s.stubs)
	}
	var named *Directive
	for _, l := range dirs(app, "location") {
		if l.Args[0] == "@app" {
			named = l
		}
	}
	if got := argLines(find(named.Block, "proxy_pass")); !reflect.DeepEqual(got, []string{"http://127.0.0.1:" + strconv.Itoa(stub)}) {
		t.Errorf("@app proxy_pass = %q", got)
	}
	if got := argLines(find(named.Block, "proxy_set_header")); !reflect.DeepEqual(got, []string{"Host 127.0.0.1:3000"}) {
		t.Errorf("@app proxy_set_header = %q, want the original host pinned", got)
	}

	api := buildScratchConf(t, s, 2)
	// A bare server fragment is wrapped in http { }.
	if len(find(api, "http")) != 1 || len(find(api, "server")) != 0 {
		t.Errorf("fragment not wrapped in http: top level = %v", names(api))
	}
	if got := argLines(dirs(api, "fastcgi_pass")); !reflect.DeepEqual(got, []string{"127.0.0.1:1"}) {
		t.Errorf("fastcgi_pass = %q, want the closed port", got)
	}
	found := false
	for n := range s.notes {
		found = found || strings.Contains(n, "fastcgi_pass backends are not stubbed")
	}
	if !found {
		t.Errorf("no note about the unstubbed FastCGI backend; notes = %v", s.notes)
	}
}

func oneHop(t *testing.T, src string) *Bundle {
	t.Helper()
	return &Bundle{Hops: []*Hop{{Name: "only", File: "only.conf", Addrs: []string{"only"}, Tree: parseStr(t, src)}}}
}

func TestBuildConfLocationFragment(t *testing.T) {
	s := newScratch(t, oneHop(t, "location / { return 200; }"), map[int]int{80: 41080})
	tree := buildScratchConf(t, s, 0)
	srv := dirs(tree, "server")
	if len(srv) != 1 {
		t.Fatalf("%d server blocks, want 1 synthetic", len(srv))
	}
	if got := argLines(find(srv[0].Block, "listen")); !reflect.DeepEqual(got, []string{"127.0.0.1:41080"}) {
		t.Errorf("listen = %q, want the default port 80 mapped", got)
	}
}

func TestBuildConfDropsAndMerges(t *testing.T) {
	s := newScratch(t, oneHop(t, `
user www-data;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
http {
    access_log /var/log/nginx/access.log;
    proxy_cache_path /var/cache/nginx keys_zone=c:10m;
    server {
        listen 443 ssl;
        listen [::]:443 ssl default_server;
        listen unix:/run/x.sock;
        ssl_certificate /etc/ssl/real.pem;
        ssl_certificate_key /etc/ssl/real.key;
        location / { proxy_cache c; return 200; }
    }
}
`), map[int]int{443: 41443})
	conf, err := s.buildConf(s.hops[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"www-data", "/run/nginx.pid", "/var/log", "/var/cache", "/etc/ssl", "x.sock", "[::]", "proxy_cache"} {
		if strings.Contains(conf, leak) {
			t.Errorf("scratch config still refers to %q:\n%s", leak, conf)
		}
	}
	// IPv4 and IPv6 listens on one port collapse into one, keeping the flags.
	if got := argLines(dirs(parseStr(t, conf), "listen")); !reflect.DeepEqual(got, []string{"127.0.0.1:41443 ssl default_server"}) {
		t.Errorf("listen = %q", got)
	}
}

func TestBuildConfHostHeader(t *testing.T) {
	s := newScratch(t, oneHop(t, `
server {
    listen 80;
    proxy_set_header X-Forwarded-For $remote_addr;
    location /plain/   { proxy_pass http://Backend.Example:8000/app/; }
    location /own/     { proxy_set_header Host custom; proxy_pass http://backend.example:8000; }
    location /other/   { proxy_set_header X-Other 1; proxy_pass https://backend.example; }
    location /dynamic/ { proxy_pass http://$http_x_target; }
    location /sock/    { proxy_pass http://unix:/run/app.sock:/uri/; }
}
`), map[int]int{80: 41080})
	tree := buildScratchConf(t, s, 0)
	locs := map[string]*Directive{}
	for _, l := range dirs(tree, "location") {
		locs[l.Args[0]] = l
	}
	stub := func(addr string) string {
		p, ok := s.stubs[addr]
		if !ok {
			t.Fatalf("no stub for %s; stubs = %v", addr, s.stubs)
		}
		return "127.0.0.1:" + strconv.Itoa(p)
	}
	check := func(loc string, wantPass string, wantHeaders ...string) {
		t.Helper()
		l := locs[loc]
		if got := argLines(find(l.Block, "proxy_pass")); !reflect.DeepEqual(got, []string{wantPass}) {
			t.Errorf("%s proxy_pass = %q, want %q", loc, got, wantPass)
		}
		if got := argLines(find(l.Block, "proxy_set_header")); !reflect.DeepEqual(got, wantHeaders) {
			t.Errorf("%s proxy_set_header = %q, want %q", loc, got, wantHeaders)
		}
	}
	// No own headers: the inherited ones are repeated (adding one here would
	// otherwise switch inheritance off) and the original Host is pinned.
	check("/plain/", "http://"+stub("backend.example:8000")+"/app/",
		"X-Forwarded-For $remote_addr", "Host Backend.Example:8000")
	// An explicit Host is respected.
	check("/own/", "http://"+stub("backend.example:8000"), "Host custom")
	// Own headers without Host: only Host is added.
	check("/other/", "https://"+stub("backend.example"), "X-Other 1", "Host backend.example")
	// Variables in the host cannot be redirected: closed port, with a note.
	check("/dynamic/", "http://127.0.0.1:1")
	// Unix sockets become stubs; the URI part after the socket path is kept.
	check("/sock/", "http://"+stub("unix:/run/app.sock")+"/uri/", "X-Forwarded-For $remote_addr", "Host localhost")

	noted := false
	for n := range s.notes {
		noted = noted || strings.Contains(n, "proxy_pass host contains variables")
	}
	if !noted {
		t.Errorf("no note for the variable proxy_pass; notes = %v", s.notes)
	}
}

func TestBuildConfRejectsLua(t *testing.T) {
	s := newScratch(t, oneHop(t, "server { location / { content_by_lua_block { ngx.say(1) } } }"), map[int]int{80: 41080})
	_, err := s.buildConf(s.hops[0])
	if err == nil || !strings.Contains(err.Error(), "Lua") {
		t.Errorf("err = %v, want a Lua-not-supported error", err)
	}
}

func TestTargetPortFallback(t *testing.T) {
	b := &Bundle{Hops: []*Hop{
		{Name: "edge", Addrs: []string{"edge"}, Tree: parseStr(t, "server { listen 80; }")},
		{Name: "app", Addrs: []string{"app", "10.0.0.5"}, Tree: parseStr(t, "server { listen 8080; listen 9090; }")},
	}}
	s := newScratch(t, b, map[int]int{80: 41080}, map[int]int{8080: 42080, 9090: 42090})
	if got, _ := s.target("10.0.0.5:9090", 80); got != "127.0.0.1:42090" {
		t.Errorf("explicit port: %s", got)
	}
	if len(s.notes) != 0 {
		t.Errorf("unexpected notes: %v", s.notes)
	}
	// Port 80 is not one of app's listeners: the lowest one is used, and said so.
	if got, _ := s.target("APP", 80); got != "127.0.0.1:42080" {
		t.Errorf("fallback port: %s", got)
	}
	if len(s.notes) != 1 {
		t.Errorf("want one note about the port fallback, got %v", s.notes)
	}
}

func TestNormLocation(t *testing.T) {
	s := &scratch{hops: []*shop{
		{ports: map[int]int{80: 41080, 443: 41443}},
		{ports: map[int]int{8080: 42080}},
	}}
	cases := []struct{ in, want string }{
		{"", ""},
		{"/relative/path", "/relative/path"},
		{"http://example.com:41080/x", "http://example.com/x"},
		{"https://example.com:41443/y?z=1", "https://example.com/y?z=1"},
		{"http://example.com:42080/z", "http://example.com:8080/z"},
		{"https://elsewhere.example/keep", "https://elsewhere.example/keep"},
	}
	for _, c := range cases {
		if got := s.normLocation(c.in); got != c.want {
			t.Errorf("normLocation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNewLocsReadsIncrementally(t *testing.T) {
	h := &shop{dir: t.TempDir()}
	log := filepath.Join(h.dir, "error.log")
	if got := h.newLocs(); got != nil {
		t.Errorf("missing log: %v", got)
	}
	first := `2026/11/24 22:00:00 [debug] 1#1: *1 test location: "/"
2026/11/24 22:00:00 [debug] 1#1: *1 using configuration "/api/"
2026/11/24 22:00:00 [debug] 1#1: *1 using location: @app "/x?"
2026/11/24 22:00:00 [debug] 1#1: *1 using configuration "=/healthz"
`
	if err := os.WriteFile(log, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, want := h.newLocs(), []string{"/api/", "@app", "=/healthz"}; !reflect.DeepEqual(got, want) {
		t.Errorf("first read = %q, want %q (in log order)", got, want)
	}
	if got := h.newLocs(); len(got) != 0 {
		t.Errorf("second read with no new lines = %q, want none", got)
	}
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("2026/11/24 22:00:01 [debug] 1#1: *2 using configuration \"\"\n")
	f.Close()
	if got, want := h.newLocs(), []string{""}; !reflect.DeepEqual(got, want) {
		t.Errorf("read after append = %q, want %q (no location matched)", got, want)
	}
}
