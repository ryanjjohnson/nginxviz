package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildBundle(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"edge.conf":      "server { listen 80; }",
		"app/nginx.conf": "server { listen 8080; }",
	})
	edge, app := filepath.Join(dir, "edge.conf"), filepath.Join(dir, "app", "nginx.conf")
	b, err := buildBundle("T", []string{edge, "App=" + app}, []string{"App=10.0.0.5:8080", "App=APP.Internal"})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Hops) != 2 {
		t.Fatalf("%d hops", len(b.Hops))
	}
	// Unnamed config: the hop is named after the file, without extension.
	if h := b.Hops[0]; h.Name != "edge" || !reflect.DeepEqual(h.Addrs, []string{"edge"}) {
		t.Errorf("hop 0 = %s %v", h.Name, h.Addrs)
	}
	// Addresses are matched case-insensitively, so they are stored lower-case.
	if h := b.Hops[1]; h.Name != "App" || h.File != app || !reflect.DeepEqual(h.Addrs, []string{"app", "10.0.0.5:8080", "app.internal"}) {
		t.Errorf("hop 1 = %s %s %v", h.Name, h.File, h.Addrs)
	}
	if b.Warnings == nil {
		t.Error("Warnings must be an empty list, not null, in the page data")
	}
}

func TestBuildBundleErrors(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a/nginx.conf": "server { }",
		"b/nginx.conf": "server { }",
		"bad.conf":     "server {",
	})
	a, bb := filepath.Join(dir, "a", "nginx.conf"), filepath.Join(dir, "b", "nginx.conf")
	cases := []struct {
		name         string
		confs, addrs []string
		want         string
	}{
		{"same default name twice", []string{a, bb}, nil, `duplicate hop name "nginx"`},
		{"addr without name", []string{a}, []string{"10.0.0.1"}, "want name=host[:port]"},
		{"addr for unknown hop", []string{a}, []string{"nope=10.0.0.1"}, `no hop named "nope"`},
		{"unparseable config", []string{filepath.Join(dir, "bad.conf")}, nil, "bad.conf:1"},
		{"missing config", []string{filepath.Join(dir, "missing.conf")}, nil, "missing.conf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildBundle("T", c.confs, c.addrs)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestViewerPlaceholders(t *testing.T) {
	if n := strings.Count(viewerHTML, "/*__NGINXVIZ_DATA__*/null"); n != 1 {
		t.Errorf("viewer.html has %d data placeholders, want exactly 1", n)
	}
	if !strings.Contains(viewerHTML, "__NGINXVIZ_TITLE__") {
		t.Error("viewer.html has no title placeholder")
	}
}

// The README promises a page that makes no network requests.
func TestViewerIsSelfContained(t *testing.T) {
	if !strings.Contains(viewerHTML, `http-equiv="Content-Security-Policy"`) || !strings.Contains(viewerHTML, "default-src 'none'") {
		t.Error("viewer.html lacks the default-src 'none' Content-Security-Policy")
	}
	lower := strings.ToLower(viewerHTML)
	for _, bad := range []string{"<script src", "<link ", "<iframe", "<img ", "@import", "fetch(", "xmlhttprequest", "websocket(", "sendbeacon"} {
		if strings.Contains(lower, bad) {
			t.Errorf("viewer.html contains %q", bad)
		}
	}
}

func TestRenderHTML(t *testing.T) {
	// A config and title that try to break out of the <script> and <title>.
	dir := writeFiles(t, map[string]string{"x.conf": `server { return 200 "</script><script>alert(1)</script>"; }`})
	b, err := buildBundle(`</title><script>alert("t")</script>`, []string{filepath.Join(dir, "x.conf")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	html, err := renderHTML(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "__NGINXVIZ_") {
		t.Error("placeholders left in the rendered page")
	}
	if strings.Contains(html, "alert(1)</script>") || strings.Contains(html, `<script>alert("t")`) {
		t.Error("config or title text reached the page unescaped")
	}
	if strings.Count(html, "<script") != strings.Count(viewerHTML, "<script") {
		t.Error("rendering changed the number of script elements")
	}
	// The embedded data must be the bundle, readable back as JSON.
	const marker = "const DATA = "
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatal("no DATA assignment in the page")
	}
	line := html[i+len(marker):]
	line = strings.TrimSuffix(strings.TrimSpace(line[:strings.IndexByte(line, '\n')]), ";")
	var back Bundle
	if err := json.Unmarshal([]byte(line), &back); err != nil {
		t.Fatalf("embedded data is not valid JSON: %v", err)
	}
	if back.Title != b.Title || len(back.Hops) != 1 || !sameTree(back.Hops[0].Tree, b.Hops[0].Tree) {
		t.Error("embedded data does not match the bundle")
	}
}

func TestExampleHTMLHasAllHops(t *testing.T) {
	html, err := renderHTML(exampleBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name":"edge"`, `"name":"app"`, `"name":"api"`, `"f":"conf.d/site.conf"`} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered example page lacks %s", want)
		}
	}
}
