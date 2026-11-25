package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// ---- small helpers over the directive tree ----

func find(ds []*Directive, name string) []*Directive {
	var out []*Directive
	for _, d := range ds {
		if d.Name == name {
			out = append(out, d)
		}
	}
	return out
}

// serverBlocks returns the http-level server blocks. Fragments are accepted:
// bare server blocks, or bare location blocks (wrapped in a synthetic server).
func serverBlocks(tree []*Directive) []*Directive {
	var out []*Directive
	for _, h := range find(tree, "http") {
		out = append(out, find(h.Block, "server")...)
	}
	out = append(out, find(tree, "server")...)
	if len(out) == 0 && len(find(tree, "location")) > 0 {
		out = append(out, &Directive{Name: "server", IsBlk: true, Block: tree})
	}
	return out
}

func upstreams(tree []*Directive) map[string][]string {
	m := map[string][]string{}
	scan := func(ds []*Directive) {
		for _, u := range find(ds, "upstream") {
			if len(u.Args) == 0 {
				continue
			}
			for _, s := range find(u.Block, "server") {
				if len(s.Args) > 0 {
					m[u.Args[0]] = append(m[u.Args[0]], strings.ToLower(s.Args[0]))
				}
			}
		}
	}
	scan(tree)
	for _, h := range find(tree, "http") {
		scan(h.Block)
	}
	return m
}

type loc struct {
	d      *Directive
	mod    string // "", "=", "^~", "~", "~*", "@"
	pat    string
	nested []*loc
}

func parseLoc(d *Directive) *loc {
	l := &loc{d: d}
	switch {
	case len(d.Args) >= 2:
		l.mod, l.pat = d.Args[0], d.Args[1]
	case len(d.Args) == 1:
		a := d.Args[0]
		switch {
		case strings.HasPrefix(a, "@"):
			l.mod, l.pat = "@", a
		case strings.HasPrefix(a, "^~"):
			l.mod, l.pat = "^~", a[2:]
		case strings.HasPrefix(a, "~*"):
			l.mod, l.pat = "~*", a[2:]
		case strings.HasPrefix(a, "~"):
			l.mod, l.pat = "~", a[1:]
		case strings.HasPrefix(a, "="):
			l.mod, l.pat = "=", a[1:]
		default:
			l.pat = a
		}
	}
	for _, c := range find(d.Block, "location") {
		l.nested = append(l.nested, parseLoc(c))
	}
	return l
}

// orderLocs approximates nginx's evaluation order as a linear decision
// chain: exact, then ^~ prefixes, then regexes in file order, then plain
// prefixes (longest first).
func orderLocs(ls []*loc) (ordered []*loc, named []*loc) {
	var exact, stop, re, pre []*loc
	for _, l := range ls {
		switch l.mod {
		case "=":
			exact = append(exact, l)
		case "^~":
			stop = append(stop, l)
		case "~", "~*":
			re = append(re, l)
		case "@":
			named = append(named, l)
		default:
			pre = append(pre, l)
		}
	}
	byLen := func(s []*loc) {
		sort.SliceStable(s, func(i, j int) bool { return len(s[i].pat) > len(s[j].pat) })
	}
	byLen(stop)
	byLen(pre)
	ordered = append(ordered, exact...)
	ordered = append(ordered, stop...)
	ordered = append(ordered, re...)
	ordered = append(ordered, pre...)
	return
}

var passDirectives = []string{"proxy_pass", "grpc_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass"}

// action summarises what a block does with a request. target is the
// proxy_pass-style destination, if any.
func action(ds []*Directive) (label, target string) {
	var parts []string
	for _, d := range ds {
		switch d.Name {
		case "rewrite", "return", "try_files", "root", "alias", "auth_request", "auth_basic", "deny", "allow", "internal", "error_page":
			parts = append(parts, d.Name+" "+strings.Join(d.Args, " "))
		case "if":
			parts = append(parts, "if "+strings.Join(d.Args, " ")+" {…}")
		}
		for _, p := range passDirectives {
			if d.Name == p && len(d.Args) > 0 {
				parts = append(parts, d.Name+" "+d.Args[0])
				if target == "" {
					target = d.Args[0]
				}
			}
		}
	}
	if len(parts) == 0 {
		return "serve static file (inherited settings)", ""
	}
	if len(parts) > 6 {
		parts = append(parts[:6], fmt.Sprintf("… +%d more", len(parts)-6))
	}
	return strings.Join(parts, "\n"), target
}

// targetHosts returns candidate host[:port] strings for a pass target.
func targetHosts(target string, ups map[string][]string) []string {
	t := target
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return nil
	}
	h := strings.ToLower(u.Host)
	if s, ok := ups[h]; ok {
		return s
	}
	return []string{h}
}

func resolveHop(b *Bundle, hosts []string) *Hop {
	for _, host := range hosts {
		bare := host
		if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.HasSuffix(host, "]") {
			bare = host[:i]
		}
		for _, h := range b.Hops {
			for _, a := range h.Addrs {
				if a == host || a == bare {
					return h
				}
			}
		}
	}
	return nil
}

// ---- mermaid output ----

type mm struct {
	sb    strings.Builder
	n     int
	cross []string // edges between hops, emitted after all subgraphs
}

func (m *mm) id(prefix string) string { m.n++; return fmt.Sprintf("%s%d", prefix, m.n) }

func esc(s string) string {
	if len(s) > 300 {
		n := 300
		for n > 0 && !utf8.RuneStart(s[n]) { // do not cut a character in half
			n--
		}
		s = s[:n] + "…"
	}
	r := strings.NewReplacer("#", "#35;", `"`, "#quot;", "<", "#lt;", ">", "#gt;", "\n", "<br/>", "`", "'")
	return r.Replace(s)
}

func (m *mm) line(indent int, format string, a ...any) {
	m.sb.WriteString(strings.Repeat("  ", indent))
	fmt.Fprintf(&m.sb, format, a...)
	m.sb.WriteByte('\n')
}

func hopEntry(i int) string { return fmt.Sprintf("hop%d_in", i) }

func Mermaid(b *Bundle) string {
	m := &mm{}
	hopIdx := map[*Hop]int{}
	for i, h := range b.Hops {
		hopIdx[h] = i
	}
	m.line(0, "flowchart TD")
	m.line(1, "client([Client request]) --> %s", hopEntry(0))
	for i, h := range b.Hops {
		ups := upstreams(h.Tree)
		m.line(1, "subgraph hop%d[\"%s — %s\"]", i, esc(h.Name), esc(h.File))
		m.line(2, "%s{{\"select server block<br/>(listen + Host header)\"}}", hopEntry(i))
		for _, s := range serverBlocks(h.Tree) {
			sid := m.id("s")
			var listens, names []string
			for _, d := range find(s.Block, "listen") {
				listens = append(listens, strings.Join(d.Args, " "))
			}
			for _, d := range find(s.Block, "server_name") {
				names = append(names, d.Args...)
			}
			if len(listens) == 0 {
				listens = []string{"80"}
			}
			if len(names) == 0 {
				names = []string{`""`}
			}
			m.line(2, "%s --> %s[\"server<br/>listen %s<br/>server_name %s\"]", hopEntry(i), sid,
				esc(strings.Join(listens, ", ")), esc(strings.Join(names, " ")))
			prev := sid
			var srvParts []*Directive
			for _, d := range s.Block {
				if d.Name != "location" {
					srvParts = append(srvParts, d)
				}
			}
			// server-level rewrite/return/if run before location matching
			var pre []string
			for _, d := range srvParts {
				if d.Name == "rewrite" || d.Name == "return" || d.Name == "if" {
					pre = append(pre, d.Name+" "+strings.Join(d.Args, " "))
				}
			}
			if len(pre) > 0 {
				pid := m.id("r")
				m.line(2, "%s --> %s[/\"server-level rewrite phase<br/>%s\"/]", prev, pid, esc(strings.Join(pre, "\n")))
				prev = pid
			}
			var locs []*loc
			for _, d := range find(s.Block, "location") {
				locs = append(locs, parseLoc(d))
			}
			m.locChain(b, hopIdx, ups, prev, "", locs, 2)
		}
		m.line(1, "end")
	}
	for _, c := range m.cross {
		m.line(1, "%s", c)
	}

	var out strings.Builder
	fmt.Fprintf(&out, "# %s\n\n", b.Title)
	out.WriteString("Generated by `nginxviz`. Hops, in order:\n\n")
	for i, h := range b.Hops {
		fmt.Fprintf(&out, "%d. **%s** — `%s` (reachable as: %s)\n", i+1, h.Name, h.File, "`"+strings.Join(h.Addrs, "`, `")+"`")
	}
	out.WriteString("\n```mermaid\n")
	out.WriteString(m.sb.String())
	out.WriteString("```\n\n")
	out.WriteString(`## Reading the diagram

- Diamonds are location tests, shown in the order nginx effectively decides them:
  exact (` + "`=`" + `), then ` + "`^~`" + ` prefixes, then regexes in file order, then plain
  prefixes (longest first).
- This linear order is a simplification. Precisely: nginx first finds the
  *longest* matching prefix location; only if that one is ` + "`^~`" + ` are regexes skipped.
  A shorter ` + "`^~`" + ` location does not suppress regexes when a longer plain prefix
  also matches. Use the interactive HTML trace for the exact behaviour on a given URL.
- Dotted edges cross from one nginx instance to the next.
`)
	if len(b.Warnings) > 0 {
		out.WriteString("\n## Warnings\n\n")
		for _, w := range b.Warnings {
			fmt.Fprintf(&out, "- %s\n", w)
		}
	}
	return out.String()
}

func locLabel(l *loc) string {
	if l.mod == "" || l.mod == "@" {
		return "location " + l.pat
	}
	return "location " + l.mod + " " + l.pat
}

// locChain emits a yes/no chain of location tests starting from node prev.
func (m *mm) locChain(b *Bundle, hopIdx map[*Hop]int, ups map[string][]string, prev, edge string, locs []*loc, ind int) {
	ordered, named := orderLocs(locs)
	link := func(from, lbl, to string) {
		if lbl == "" {
			m.line(ind, "%s --> %s", from, to)
		} else {
			m.line(ind, "%s -->|%s| %s", from, lbl, to)
		}
	}
	emitAction := func(from, lbl string, l *loc) {
		label, target := action(l.d.Block)
		aid := m.id("a")
		m.line(ind, "%s[\"%s\"]", aid, esc(label))
		link(from, lbl, aid)
		if target != "" {
			hosts := targetHosts(target, ups)
			if h := resolveHop(b, hosts); h != nil {
				m.cross = append(m.cross, fmt.Sprintf("%s -.->|proxied| %s", aid, hopEntry(hopIdx[h])))
			} else if len(hosts) > 0 {
				eid := m.id("x")
				m.cross = append(m.cross, fmt.Sprintf("%s -.-> %s([\"external: %s\"])", aid, eid, esc(strings.Join(hosts, ", "))))
			}
		}
		if len(l.nested) > 0 {
			m.locChain(b, hopIdx, ups, aid, "nested", l.nested, ind)
		}
	}
	for _, l := range ordered {
		did := m.id("l")
		m.line(ind, "%s{\"%s ?\"}", did, esc(locLabel(l)))
		link(prev, edge, did)
		emitAction(did, "yes", l)
		prev, edge = did, "no"
	}
	if len(ordered) > 0 {
		nid := m.id("n")
		m.line(ind, "%s[\"no location matched:<br/>server-level handling / 404\"]", nid)
		link(prev, edge, nid)
	}
	for _, l := range named {
		nid := m.id("l")
		m.line(ind, "%s[[\"named %s<br/>(internal redirect target)\"]]", nid, esc(l.pat))
		emitAction(nid, "", l)
	}
}
