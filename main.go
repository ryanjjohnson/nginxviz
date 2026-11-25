// nginxviz turns one or more nginx configurations into
//   - a single self-contained interactive HTML page (no network access,
//     no external scripts/fonts/styles) that traces a URL step by step
//     through the configs, and
//   - a Markdown file with a Mermaid flow diagram / decision tree.
//
// Standard library only.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed viewer.html
var viewerHTML string

// Hop is one nginx instance (one config) in the chain.
type Hop struct {
	Name  string       `json:"name"`
	File  string       `json:"file"`
	Addrs []string     `json:"addrs"` // host[:port] values that route to this hop
	Tree  []*Directive `json:"tree"`
}

type Bundle struct {
	Title    string   `json:"title"`
	Hops     []*Hop   `json:"hops"`
	Warnings []string `json:"warnings"`
	Verify   *Verify  `json:"verify,omitempty"`
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func usage() {
	fmt.Fprint(os.Stderr, `nginxviz - interactive nginx config request tracer

Usage:
  nginxviz [flags] [name=]nginx.conf [[name=]other.conf ...]

Each config is one nginx instance ("hop"). The first one is the entry point.
When a proxy_pass (or upstream server) points at an address registered for
another hop, the trace continues in that hop's config.

Flags:
  -addr name=host[:port]   address that reaches hop <name> (repeatable).
                           A hop is always reachable by its own name.
  -o dir                   output directory (default ".")
  -name base               output file base name (default "nginx-flow")
  -title text              title shown in the outputs
  -verify urls.txt         replay the URLs in this file against a real nginx
                           running scratch copies of the configs (127.0.0.1
                           only, backends stubbed) and embed what nginx did in
                           the HTML, next to the simulation. One per line:
                             [METHOD] URL [ | Header: value]...
  -nginx path              nginx binary for -verify (default "nginx")
  -keep                    keep the scratch directory of a -verify run

Example:
  nginxviz -addr app=10.0.0.5:8080 -addr api=api.internal:9000 \
           edge=edge/nginx.conf app=app/nginx.conf api=api/nginx.conf

Outputs <base>.html (fully self-contained, works offline) and <base>.md.
`)
}

func main() {
	var addrs multiFlag
	outDir := flag.String("o", ".", "output directory")
	base := flag.String("name", "nginx-flow", "output base name")
	title := flag.String("title", "nginx request flow", "title")
	flag.Var(&addrs, "addr", "name=host[:port] (repeatable)")
	verifyFile := flag.String("verify", "", "file with URLs to replay against real nginx")
	nginxBin := flag.String("nginx", "nginx", "nginx binary for -verify")
	keep := flag.Bool("keep", false, "keep the -verify scratch directory")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}

	b, err := buildBundle(*title, flag.Args(), addrs)
	if err != nil {
		fatal("%v", err)
	}

	if *verifyFile != "" {
		v, err := RunVerify(b, *nginxBin, *verifyFile, *keep)
		if err != nil {
			fatal("verify: %v", err)
		}
		b.Verify = v
		fmt.Printf("verify: replayed %d request(s) against %s\n", len(v.Cases), v.Nginx)
		for _, c := range v.Cases {
			res := fmt.Sprintf("status %d", c.Status)
			if c.Error != "" {
				res = c.Error
			}
			fmt.Printf("  %-6s %s -> %s\n", c.Method, c.URL, res)
		}
		fmt.Println("verify: open the HTML to see where nginx and the simulation agree or differ")
	}

	html, err := renderHTML(b)
	if err != nil {
		fatal("%v", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal("%v", err)
	}
	htmlPath := filepath.Join(*outDir, *base+".html")
	mdPath := filepath.Join(*outDir, *base+".md")
	if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
		fatal("%v", err)
	}
	if err := os.WriteFile(mdPath, []byte(Mermaid(b)), 0o644); err != nil {
		fatal("%v", err)
	}
	for _, w := range b.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	fmt.Println("wrote", htmlPath)
	fmt.Println("wrote", mdPath)
}

// buildBundle parses each [name=]path config into a hop and attaches the
// -addr name=host[:port] mappings.
func buildBundle(title string, confs, addrs []string) (*Bundle, error) {
	b := &Bundle{Title: title, Warnings: []string{}}
	byName := map[string]*Hop{}
	for _, arg := range confs {
		name, path := "", arg
		if i := strings.IndexByte(arg, '='); i > 0 {
			name, path = arg[:i], arg[i+1:]
		} else {
			name = strings.TrimSuffix(filepath.Base(arg), filepath.Ext(arg))
		}
		if byName[name] != nil {
			return nil, fmt.Errorf("duplicate hop name %q (use name=path to disambiguate)", name)
		}
		tree, err := ParseFile(path, &b.Warnings)
		if err != nil {
			return nil, err
		}
		h := &Hop{Name: name, File: path, Addrs: []string{strings.ToLower(name)}, Tree: tree}
		byName[name] = h
		b.Hops = append(b.Hops, h)
	}
	for _, a := range addrs {
		i := strings.IndexByte(a, '=')
		if i <= 0 {
			return nil, fmt.Errorf("-addr %q: want name=host[:port]", a)
		}
		h := byName[a[:i]]
		if h == nil {
			return nil, fmt.Errorf("-addr %q: no hop named %q", a, a[:i])
		}
		h.Addrs = append(h.Addrs, strings.ToLower(a[i+1:]))
	}
	return b, nil
}

// renderHTML embeds the bundle in the viewer page.
func renderHTML(b *Bundle) (string, error) {
	data, err := json.Marshal(b) // escapes <, >, & and U+2028/9: safe in <script>
	if err != nil {
		return "", err
	}
	html := strings.Replace(viewerHTML, "/*__NGINXVIZ_DATA__*/null", string(data), 1)
	return strings.Replace(html, "__NGINXVIZ_TITLE__", htmlEscape(b.Title), -1), nil
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "nginxviz: "+format+"\n", a...)
	os.Exit(1)
}
