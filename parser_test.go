package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeFiles creates files (path relative to a fresh temp dir -> content)
// and returns the directory.
func writeFiles(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func parseStr(t testing.TB, src string) []*Directive {
	t.Helper()
	dir := writeFiles(t, map[string]string{"nginx.conf": src})
	var warns []string
	ds, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	if len(warns) > 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	return ds
}

func parseErr(t testing.TB, src string) error {
	t.Helper()
	dir := writeFiles(t, map[string]string{"nginx.conf": src})
	var warns []string
	_, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	return err
}

// sameTree compares the parts of two trees that carry meaning
// (names, arguments, block structure), ignoring positions and quoting.
func sameTree(a, b []*Directive) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Name != y.Name || x.IsBlk != y.IsBlk || len(x.Args) != len(y.Args) {
			return false
		}
		for j := range x.Args {
			if x.Args[j] != y.Args[j] {
				return false
			}
		}
		if !sameTree(x.Block, y.Block) {
			return false
		}
	}
	return true
}

func TestParseBasic(t *testing.T) {
	ds := parseStr(t, `# leading comment
worker_processes auto;
http {
    server {            # trailing comment
        listen 80;
        location / { }
    }
}
`)
	if len(ds) != 2 {
		t.Fatalf("got %d top-level directives, want 2", len(ds))
	}
	wp := ds[0]
	if wp.Name != "worker_processes" || !reflect.DeepEqual(wp.Args, []string{"auto"}) || wp.IsBlk {
		t.Errorf("worker_processes parsed as %+v", wp)
	}
	if wp.File != "nginx.conf" || wp.Line != 2 {
		t.Errorf("position = %s:%d, want nginx.conf:2", wp.File, wp.Line)
	}
	http := ds[1]
	if http.Name != "http" || !http.IsBlk || len(http.Block) != 1 {
		t.Fatalf("http parsed as %+v", http)
	}
	srv := http.Block[0]
	if srv.Line != 4 || len(srv.Block) != 2 {
		t.Fatalf("server: line %d, %d children", srv.Line, len(srv.Block))
	}
	loc := srv.Block[1]
	if loc.Name != "location" || !loc.IsBlk || len(loc.Block) != 0 || loc.Line != 6 {
		t.Errorf("empty location block parsed as %+v", loc)
	}
}

func TestParseQuoting(t *testing.T) {
	ds := parseStr(t, `
return 200 "say \"hi\"";
set $a 'it\'s';
location ~ "\.php$" { }
set $b "two
lines";
after here;
add_header X "a;b{c}";
set $c pre${host}post;
"quoted name" x;
set $d "";
`)
	want := []struct {
		args []string
		q    []bool
	}{
		{[]string{"200", `say "hi"`}, []bool{false, true}},
		{[]string{"$a", "it's"}, []bool{false, true}},
		{[]string{"~", `\.php$`}, []bool{false, true}}, // regex backslash kept
		{[]string{"$b", "two\nlines"}, []bool{false, true}},
		{[]string{"here"}, []bool{false}},
		{[]string{"X", "a;b{c}"}, []bool{false, true}},
		{[]string{"$c", "pre${host}post"}, []bool{false, false}},
		{[]string{"x"}, []bool{false}},
		{[]string{"$d", ""}, []bool{false, true}},
	}
	if len(ds) != len(want) {
		t.Fatalf("got %d directives, want %d", len(ds), len(want))
	}
	for i, w := range want {
		if !reflect.DeepEqual(ds[i].Args, w.args) {
			t.Errorf("directive %d (%s): args %q, want %q", i, ds[i].Name, ds[i].Args, w.args)
		}
		if !reflect.DeepEqual(ds[i].Q, w.q) {
			t.Errorf("directive %d (%s): quoted flags %v, want %v", i, ds[i].Name, ds[i].Q, w.q)
		}
	}
	// A quoted string spanning two lines must advance the line counter.
	if ds[4].Name != "after" || ds[4].Line != 7 {
		t.Errorf("directive after multi-line string is %s at line %d, want after at line 7", ds[4].Name, ds[4].Line)
	}
	if ds[7].Name != "quoted name" || !ds[7].NQ {
		t.Errorf("quoted directive name parsed as %+v", ds[7])
	}
}

func TestParseUnquotedRegex(t *testing.T) {
	ds := parseStr(t, `location ~ ^/v1/posts/(?<id>[^/]+)\.json$ { return 204; }`)
	if got := ds[0].Args; !reflect.DeepEqual(got, []string{"~", `^/v1/posts/(?<id>[^/]+)\.json$`}) {
		t.Errorf("args = %q", got)
	}
}

func TestParseLuaBlockSkipped(t *testing.T) {
	ds := parseStr(t, `
location /lua {
    content_by_lua_block {
        local t = { a = 1 }
        if t.a then ngx.say("x; y") end
    }
    return 200;
}
`)
	loc := ds[0]
	if len(loc.Block) != 2 {
		t.Fatalf("location has %d children, want 2", len(loc.Block))
	}
	lua := loc.Block[0]
	if lua.Name != "content_by_lua_block" || !lua.IsBlk || len(lua.Block) != 0 {
		t.Errorf("lua block parsed as %+v", lua)
	}
	if ret := loc.Block[1]; ret.Name != "return" || ret.Line != 7 {
		t.Errorf("directive after lua block: %s at line %d, want return at line 7", ret.Name, ret.Line)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"unterminated quote", `set $a "oops;`, "unterminated quoted string"},
		{"missing semicolon at EOF", `listen 80`, `missing ";"`},
		{"missing semicolon before brace", "server { listen 80 }", `unexpected "}" in directive "listen"`},
		{"stray close brace", "}", `unexpected "}"`},
		{"unclosed block", "http { server {", `expecting "}"`},
		{"stray semicolon", ";", `unexpected ";"`},
		{"stray open brace", "{", `unexpected "{"`},
		{"unterminated variable brace", "set $a ${host;", "unterminated ${"},
		{"unterminated lua block", "content_by_lua_block { x = {", "unterminated raw block"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := parseErr(t, c.src)
			if err == nil {
				t.Fatalf("no error for %q", c.src)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
			if !strings.Contains(err.Error(), "nginx.conf:") {
				t.Errorf("error %q has no file:line prefix", err)
			}
		})
	}
}

func TestParseErrorLine(t *testing.T) {
	err := parseErr(t, "a 1;\nb 2;\n}\n")
	if err == nil || !strings.HasPrefix(err.Error(), "nginx.conf:3:") {
		t.Errorf("error = %v, want prefix nginx.conf:3:", err)
	}
}

func TestParseMissingFile(t *testing.T) {
	var warns []string
	if _, err := ParseFile(filepath.Join(t.TempDir(), "nope.conf"), &warns); err == nil {
		t.Error("no error for a missing file")
	}
}

func TestInclude(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"nginx.conf":        "http {\n    include conf.d/*.conf;\n    include mime.types;\n}\n",
		"conf.d/b.conf":     "server { server_name b; }\n",
		"conf.d/a.conf":     "server { server_name a; }\n",
		"conf.d/ignored.md": "this is not nginx syntax {",
		"mime.types":        "types { text/html html; }\n",
	})
	var warns []string
	ds, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	kids := ds[0].Block
	if len(kids) != 3 {
		t.Fatalf("http has %d children, want 3 (include directives are replaced by their content)", len(kids))
	}
	// Glob matches are spliced in sorted order, with file names relative to
	// the directory of the top-level config.
	for i, want := range []struct{ name, file, arg string }{
		{"server", "conf.d/a.conf", "a"},
		{"server", "conf.d/b.conf", "b"},
		{"types", "mime.types", ""},
	} {
		d := kids[i]
		if d.Name != want.name || d.File != want.file {
			t.Errorf("child %d = %s from %s, want %s from %s", i, d.Name, d.File, want.name, want.file)
		}
		if want.arg != "" && d.Block[0].Args[0] != want.arg {
			t.Errorf("child %d server_name = %s, want %s", i, d.Block[0].Args[0], want.arg)
		}
	}
}

func TestIncludeRelativeToTopLevelDir(t *testing.T) {
	// nginx resolves relative includes against its prefix, not against the
	// including file; an include inside conf.d/ therefore names paths from
	// the top-level directory.
	dir := writeFiles(t, map[string]string{
		"nginx.conf":       "include conf.d/site.conf;\n",
		"conf.d/site.conf": "server { include snippets/x.conf; }\n",
		"snippets/x.conf":  "listen 81;\n",
	})
	var warns []string
	ds, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	l := ds[0].Block[0]
	if l.Name != "listen" || l.File != "snippets/x.conf" {
		t.Errorf("got %s from %s, want listen from snippets/x.conf", l.Name, l.File)
	}
}

func TestIncludeNoMatchWarns(t *testing.T) {
	dir := writeFiles(t, map[string]string{"nginx.conf": "a 1;\ninclude missing/*.conf;\nb 2;\n"})
	var warns []string
	ds, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[0].Name != "a" || ds[1].Name != "b" {
		t.Errorf("directives = %v", names(ds))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "matched no files") || !strings.HasPrefix(warns[0], "nginx.conf:2:") {
		t.Errorf("warnings = %q, want one 'matched no files' warning at nginx.conf:2", warns)
	}
}

func TestIncludeCycle(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"nginx.conf": "include other.conf;\n",
		"other.conf": "include nginx.conf;\n",
	})
	var warns []string
	_, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err == nil || !strings.Contains(err.Error(), "include depth") {
		t.Errorf("error = %v, want an include depth error", err)
	}
}

func TestIncludeErrorNamesIncludedFile(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"nginx.conf":      "include conf.d/bad.conf;\n",
		"conf.d/bad.conf": "ok 1;\nserver {\n",
	})
	var warns []string
	_, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err == nil || !strings.Contains(err.Error(), "conf.d/bad.conf:") {
		t.Errorf("error = %v, want it to name conf.d/bad.conf", err)
	}
}

func names(ds []*Directive) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return out
}
