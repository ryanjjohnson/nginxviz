package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseLoc(t *testing.T) {
	cases := []struct {
		src      string
		mod, pat string
	}{
		{"location / { }", "", "/"},
		{"location = /healthz { }", "=", "/healthz"},
		{"location =/healthz { }", "=", "/healthz"},
		{"location ^~ /static/ { }", "^~", "/static/"},
		{"location ^~/static/ { }", "^~", "/static/"},
		{`location ~ \.php$ { }`, "~", `\.php$`},
		{`location ~\.php$ { }`, "~", `\.php$`},
		{`location ~* \.(png|gif)$ { }`, "~*", `\.(png|gif)$`},
		{`location ~*\.(png|gif)$ { }`, "~*", `\.(png|gif)$`},
		{"location @app { }", "@", "@app"},
	}
	for _, c := range cases {
		l := parseLoc(parseStr(t, c.src)[0])
		if l.mod != c.mod || l.pat != c.pat {
			t.Errorf("%s: mod %q pat %q, want mod %q pat %q", c.src, l.mod, l.pat, c.mod, c.pat)
		}
	}
}

func TestParseLocNested(t *testing.T) {
	l := parseLoc(parseStr(t, `location /a/ { location /a/b/ { } location ~ \.x$ { } return 200; }`)[0])
	if len(l.nested) != 2 || l.nested[0].pat != "/a/b/" || l.nested[1].mod != "~" {
		t.Errorf("nested = %+v", l.nested)
	}
}

func TestOrderLocs(t *testing.T) {
	ds := parseStr(t, `
location / { }
location ~ first { }
location /images/ { }
location ^~ /s/ { }
location @named { }
location ~* second { }
location = /exact { }
location /images/big/ { }
location ^~ /static/ { }
`)
	var ls []*loc
	for _, d := range ds {
		ls = append(ls, parseLoc(d))
	}
	ordered, named := orderLocs(ls)
	var got []string
	for _, l := range ordered {
		got = append(got, locLabel(l))
	}
	want := []string{
		"location = /exact",    // exact first
		"location ^~ /static/", // ^~ prefixes, longest first
		"location ^~ /s/",
		"location ~ first", // regexes in file order
		"location ~* second",
		"location /images/big/", // plain prefixes, longest first
		"location /images/",
		"location /",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order:\n got %q\nwant %q", got, want)
	}
	if len(named) != 1 || locLabel(named[0]) != "location @named" {
		t.Errorf("named = %v", named)
	}
}

func TestServerBlocks(t *testing.T) {
	full := parseStr(t, "http { server { listen 80; } server { listen 81; } }")
	if n := len(serverBlocks(full)); n != 2 {
		t.Errorf("http-wrapped: %d servers, want 2", n)
	}
	bare := parseStr(t, "server { listen 80; }")
	if n := len(serverBlocks(bare)); n != 1 {
		t.Errorf("bare server fragment: %d servers, want 1", n)
	}
	frag := parseStr(t, "location / { return 200; }\nlocation /a { return 201; }")
	s := serverBlocks(frag)
	if len(s) != 1 || len(find(s[0].Block, "location")) != 2 {
		t.Errorf("bare locations should be wrapped in one synthetic server, got %d", len(s))
	}
	if n := len(serverBlocks(parseStr(t, "worker_processes 1;"))); n != 0 {
		t.Errorf("config without servers: %d servers, want 0", n)
	}
}

func TestUpstreams(t *testing.T) {
	tree := parseStr(t, `
upstream top { server 10.0.0.1:80; }
http {
    upstream Pool { least_conn; server APP.internal:8080 weight=2; server 10.0.0.6:8080 backup; }
}
`)
	got := upstreams(tree)
	want := map[string][]string{
		"top":  {"10.0.0.1:80"},
		"Pool": {"app.internal:8080", "10.0.0.6:8080"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("upstreams = %v, want %v", got, want)
	}
}

func TestTargetHosts(t *testing.T) {
	ups := map[string][]string{"app_pool": {"10.0.0.5:8080", "10.0.0.6:8080"}}
	cases := []struct {
		target string
		want   []string
	}{
		{"http://app_pool", []string{"10.0.0.5:8080", "10.0.0.6:8080"}},
		{"http://app_pool/prefix/", []string{"10.0.0.5:8080", "10.0.0.6:8080"}},
		{"https://API.internal:9000/v1/", []string{"api.internal:9000"}},
		{"127.0.0.1:9000", []string{"127.0.0.1:9000"}}, // fastcgi_pass style, no scheme
		{"http://[::1]:8080/", []string{"[::1]:8080"}},
	}
	for _, c := range cases {
		if got := targetHosts(c.target, ups); !reflect.DeepEqual(got, c.want) {
			t.Errorf("targetHosts(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestResolveHop(t *testing.T) {
	edge := &Hop{Name: "edge", Addrs: []string{"edge"}}
	app := &Hop{Name: "app", Addrs: []string{"app", "10.0.0.5:8080"}}
	api := &Hop{Name: "api", Addrs: []string{"api", "api.internal"}}
	b := &Bundle{Hops: []*Hop{edge, app, api}}
	cases := []struct {
		hosts []string
		want  *Hop
	}{
		{[]string{"10.0.0.5:8080"}, app},
		{[]string{"app"}, app},
		{[]string{"app:1234"}, app},          // registered by name, any port
		{[]string{"api.internal:9000"}, api}, // registered without port
		{[]string{"10.0.0.5:9999"}, nil},     // registered with a different port
		{[]string{"10.0.0.9:1", "api"}, api}, // first resolvable candidate wins
		{[]string{"elsewhere.example"}, nil},
		{nil, nil},
	}
	for _, c := range cases {
		if got := resolveHop(b, c.hosts); got != c.want {
			t.Errorf("resolveHop(%v) = %v, want %v", c.hosts, hopName(got), hopName(c.want))
		}
	}
}

func hopName(h *Hop) string {
	if h == nil {
		return "<none>"
	}
	return h.Name
}

func TestAction(t *testing.T) {
	label, target := action(parseStr(t, `
proxy_set_header Host $host;
allow 10.0.0.0/8;
deny all;
proxy_pass http://app_pool/x;
`))
	if target != "http://app_pool/x" {
		t.Errorf("target = %q", target)
	}
	if want := "allow 10.0.0.0/8\ndeny all\nproxy_pass http://app_pool/x"; label != want {
		t.Errorf("label = %q, want %q", label, want)
	}

	label, target = action(parseStr(t, "expires 30d;"))
	if target != "" || !strings.Contains(label, "static file") {
		t.Errorf("block with no routing directives: label %q target %q", label, target)
	}

	label, _ = action(parseStr(t, "if ($is_bot) { return 403; }"))
	if label != "if ($is_bot) {…}" {
		t.Errorf("if label = %q", label)
	}

	label, _ = action(parseStr(t, "return 1; return 2; return 3; return 4; return 5; return 6; return 7; return 8;"))
	lines := strings.Split(label, "\n")
	if len(lines) != 7 || lines[6] != "… +2 more" {
		t.Errorf("long action list not truncated to 6 + summary: %q", lines)
	}
}

func TestEsc(t *testing.T) {
	if got, want := esc("a \"b\" <c> #d `e`\nf"), "a #quot;b#quot; #lt;c#gt; #35;d 'e'<br/>f"; got != want {
		t.Errorf("esc = %q, want %q", got, want)
	}
	long := esc(strings.Repeat("x", 500))
	if !strings.HasSuffix(long, "…") || strings.Count(long, "x") != 300 {
		t.Errorf("long label not truncated to 300: %d x", strings.Count(long, "x"))
	}
	// Truncation must not cut a multi-byte character in half.
	if got := esc("x" + strings.Repeat("é", 400)); !utf8.ValidString(got) {
		t.Error("truncating a non-ASCII label produced invalid UTF-8")
	}
}

func exampleBundle(t testing.TB) *Bundle {
	t.Helper()
	b, err := buildBundle("Example: edge → app → api",
		[]string{"edge=examples/edge/nginx.conf", "app=examples/app/nginx.conf", "api=examples/api/nginx.conf"},
		[]string{"app=10.0.0.5:8080", "app=10.0.0.6:8080", "api=api.internal:9000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Warnings) != 0 {
		t.Fatalf("example configs produced warnings: %v", b.Warnings)
	}
	return b
}

// The checked-in example output must be what the current code produces.
// If this fails after an intended change, regenerate examples/out (README).
func TestMermaidExampleGolden(t *testing.T) {
	want, err := os.ReadFile("examples/out/nginx-flow.md")
	if err != nil {
		t.Fatal(err)
	}
	got := Mermaid(exampleBundle(t))
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("differs from examples/out/nginx-flow.md at line %d:\n got %q\nwant %q", i+1, gl[i], wl[i])
			}
		}
		t.Fatalf("differs from examples/out/nginx-flow.md in length: %d vs %d lines", len(gl), len(wl))
	}
}

func TestMermaidStructure(t *testing.T) {
	md := Mermaid(exampleBundle(t))
	i, j := strings.Index(md, "```mermaid\n"), strings.LastIndex(md, "```\n")
	if i < 0 || j <= i {
		t.Fatal("no fenced mermaid block")
	}
	chart := md[i+len("```mermaid\n") : j]
	lines := strings.Split(strings.TrimRight(chart, "\n"), "\n")
	if lines[0] != "flowchart TD" {
		t.Errorf("first line = %q", lines[0])
	}
	sub, end := 0, 0
	for _, l := range lines {
		switch s := strings.TrimSpace(l); {
		case strings.HasPrefix(s, "subgraph "):
			sub++
		case s == "end":
			end++
		}
		if strings.Count(l, `"`)%2 != 0 {
			t.Errorf("unbalanced quotes in mermaid line: %s", l)
		}
	}
	if sub != 3 || end != 3 {
		t.Errorf("%d subgraph / %d end lines, want 3 / 3", sub, end)
	}
	for _, want := range []string{
		"client([Client request]) --> hop0_in",
		"-.->|proxied| hop1_in",          // edge -> app through upstream app_pool
		"-.->|proxied| hop2_in",          // app -> api through upstream api_backend
		`(["external: 127.0.0.1:3000"])`, // app's @app backend has no config
		"server-level rewrite phase",     // edge's if + rewrite before locations
		`[["named @app<br/>(internal redirect target)"]]`,
	} {
		if !strings.Contains(chart, want) {
			t.Errorf("mermaid chart lacks %q", want)
		}
	}
}

func TestMermaidWarningsSection(t *testing.T) {
	b := &Bundle{Title: "t", Hops: []*Hop{{Name: "a", File: "a.conf", Addrs: []string{"a"}}}}
	if strings.Contains(Mermaid(b), "## Warnings") {
		t.Error("warnings section present without warnings")
	}
	b.Warnings = []string{"a.conf:3: include \"x\" matched no files (skipped)"}
	if md := Mermaid(b); !strings.Contains(md, "## Warnings\n\n- a.conf:3:") {
		t.Error("warnings section missing")
	}
}

func TestMermaidDefaultsForBareServer(t *testing.T) {
	b := &Bundle{Title: "t", Hops: []*Hop{{Name: "a", File: "a.conf", Addrs: []string{"a"},
		Tree: parseStr(t, "server { location / { return 200; } }")}}}
	md := Mermaid(b)
	if !strings.Contains(md, `listen 80<br/>server_name #quot;#quot;`) {
		t.Errorf("server without listen/server_name should show nginx's defaults:\n%s", md)
	}
}
