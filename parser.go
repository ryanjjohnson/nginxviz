package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Directive is one nginx directive, optionally with a block of children.
type Directive struct {
	Name  string       `json:"n"`
	Args  []string     `json:"a,omitempty"`
	Block []*Directive `json:"b,omitempty"`
	IsBlk bool         `json:"k,omitempty"` // has a { } block (even if empty)
	Q     []bool       `json:"-"`           // per-arg: was quoted in the source
	NQ    bool         `json:"-"`           // name token was quoted
	File  string       `json:"f,omitempty"`
	Line  int          `json:"l,omitempty"`
}

type token struct {
	val    string
	line   int
	quoted bool
}

type parser struct {
	file     string // display name
	src      []byte
	pos      int
	line     int
	root     string // directory that relative includes resolve against
	depth    int
	warnings *[]string
}

const maxIncludeDepth = 20

// ParseFile parses an nginx config file, following include directives.
func ParseFile(path string, warnings *[]string) ([]*Directive, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return parseFile(abs, filepath.Dir(abs), 0, warnings)
}

func parseFile(path, root string, depth int, warnings *[]string) ([]*Directive, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("%s: include depth exceeds %d (include cycle?)", path, maxIncludeDepth)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel = path
	}
	p := &parser{file: filepath.ToSlash(rel), src: src, line: 1, root: root, depth: depth, warnings: warnings}
	ds, err := p.parseBlock(true)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %v", p.file, p.line, err)
	}
	return ds, nil
}

func (p *parser) warn(format string, a ...any) {
	*p.warnings = append(*p.warnings, fmt.Sprintf("%s:%d: ", p.file, p.line)+fmt.Sprintf(format, a...))
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\n' {
			p.line++
			p.pos++
		} else if isSpace(c) {
			p.pos++
		} else if c == '#' {
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		} else {
			return
		}
	}
}

// next returns the next token; ok=false at EOF.
func (p *parser) next() (token, bool, error) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return token{}, false, nil
	}
	start := p.line
	c := p.src[p.pos]
	if c == ';' || c == '{' || c == '}' {
		p.pos++
		return token{val: string(c), line: start}, true, nil
	}
	var sb strings.Builder
	if c == '"' || c == '\'' {
		q := c
		p.pos++
		for {
			if p.pos >= len(p.src) {
				return token{}, false, fmt.Errorf("unterminated quoted string starting on line %d", start)
			}
			ch := p.src[p.pos]
			if ch == '\\' && p.pos+1 < len(p.src) {
				nx := p.src[p.pos+1]
				// nginx only unescapes the quote char and backslash-ish
				// sequences; everything else keeps its backslash (regexes).
				if nx == q || nx == '\\' {
					sb.WriteByte(nx)
				} else {
					sb.WriteByte(ch)
					sb.WriteByte(nx)
				}
				if nx == '\n' {
					p.line++
				}
				p.pos += 2
				continue
			}
			if ch == q {
				p.pos++
				break
			}
			if ch == '\n' {
				p.line++
			}
			sb.WriteByte(ch)
			p.pos++
		}
		return token{val: sb.String(), line: start, quoted: true}, true, nil
	}
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if isSpace(ch) || ch == ';' || ch == '{' {
			break
		}
		if ch == '}' {
			break
		}
		if ch == '$' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '{' {
			// ${var} inside a bare word
			end := strings.IndexByte(string(p.src[p.pos:]), '}')
			if end < 0 {
				return token{}, false, fmt.Errorf("unterminated ${ in word")
			}
			sb.Write(p.src[p.pos : p.pos+end+1])
			p.pos += end + 1
			continue
		}
		if ch == '\\' && p.pos+1 < len(p.src) {
			sb.WriteByte(ch)
			sb.WriteByte(p.src[p.pos+1])
			p.pos += 2
			continue
		}
		sb.WriteByte(ch)
		p.pos++
	}
	return token{val: sb.String(), line: start}, true, nil
}

// skipRawBlock consumes a balanced { ... } body (for *_by_lua_block etc.)
// whose content is not nginx syntax. The opening brace is already consumed.
func (p *parser) skipRawBlock() error {
	depth := 1
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\n':
			p.line++
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				p.pos++
				return nil
			}
		}
		p.pos++
	}
	return fmt.Errorf("unterminated raw block")
}

func (p *parser) parseBlock(top bool) ([]*Directive, error) {
	var out []*Directive
	for {
		t, ok, err := p.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			if top {
				return out, nil
			}
			return nil, fmt.Errorf("unexpected end of file, expecting \"}\"")
		}
		if !t.quoted && t.val == "}" {
			if top {
				return nil, fmt.Errorf("unexpected \"}\"")
			}
			return out, nil
		}
		if !t.quoted && (t.val == ";" || t.val == "{") {
			return nil, fmt.Errorf("unexpected %q", t.val)
		}
		d := &Directive{Name: t.val, NQ: t.quoted, File: p.file, Line: t.line}
		for {
			a, ok, err := p.next()
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("unexpected end of file in directive %q (missing \";\"?)", d.Name)
			}
			if !a.quoted && a.val == ";" {
				break
			}
			if !a.quoted && a.val == "}" {
				return nil, fmt.Errorf("unexpected \"}\" in directive %q (missing \";\"?)", d.Name)
			}
			if !a.quoted && a.val == "{" {
				d.IsBlk = true
				if strings.HasSuffix(d.Name, "_by_lua_block") {
					if err := p.skipRawBlock(); err != nil {
						return nil, err
					}
					break
				}
				kids, err := p.parseBlock(false)
				if err != nil {
					return nil, err
				}
				d.Block = kids
				break
			}
			d.Args = append(d.Args, a.val)
			d.Q = append(d.Q, a.quoted)
		}
		if d.Name == "include" && !d.IsBlk && len(d.Args) == 1 {
			inc, err := p.include(d.Args[0])
			if err != nil {
				return nil, err
			}
			out = append(out, inc...)
			continue
		}
		out = append(out, d)
	}
}

func (p *parser) include(pattern string) ([]*Directive, error) {
	full := pattern
	if !filepath.IsAbs(full) {
		full = filepath.Join(p.root, full)
	}
	matches, err := filepath.Glob(full)
	if err != nil {
		return nil, fmt.Errorf("bad include pattern %q: %v", pattern, err)
	}
	if len(matches) == 0 {
		// nginx tolerates empty globs; a missing literal file is an error
		// there, but for analysis we warn and continue.
		p.warn("include %q matched no files (skipped)", pattern)
		return nil, nil
	}
	sort.Strings(matches)
	var out []*Directive
	for _, m := range matches {
		ds, err := parseFile(m, p.root, p.depth+1, p.warnings)
		if err != nil {
			return nil, err
		}
		out = append(out, ds...)
	}
	return out, nil
}
