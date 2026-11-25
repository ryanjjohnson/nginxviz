package main

import (
	"fmt"
	"io"
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
	depth    int    // include depth
	nest     int    // { } depth, counted across includes
	job      *parseJob
	warnings *[]string
}

// parseJob is what one top-level config (with all its includes) has used of
// its limits, and where its includes may read from.
type parseJob struct {
	dirs       []string // includes may only read files inside these directories
	files      int
	bytes      int64
	directives int
}

// ParseFile parses an nginx config file, following include directives.
//
// Includes may only read regular files inside the directory of the top-level
// config or inside one of extraDirs; anything else is skipped with a warning.
// A config can therefore not make nginxviz read (and copy into its outputs)
// files from elsewhere on the machine.
func ParseFile(path string, warnings *[]string, extraDirs ...string) ([]*Directive, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(abs)
	job := &parseJob{}
	for _, d := range append([]string{root}, extraDirs...) {
		if d, err = filepath.Abs(d); err != nil {
			return nil, err
		}
		job.dirs = append(job.dirs, d)
		// The same directory as reached through symbolic links, so that both
		// spellings of a path are recognised (/etc and /private/etc on a Mac).
		if real, err := filepath.EvalSymlinks(d); err == nil && real != d {
			job.dirs = append(job.dirs, real)
		}
	}
	return parseFile(abs, root, 0, 0, job, warnings)
}

// parseBytes parses config text held in memory, as if it were a file in
// directory root.
func parseBytes(src []byte, root string, warnings *[]string) ([]*Directive, error) {
	if len(src) > maxFileBytes {
		return nil, fmt.Errorf("config is larger than %d MB", maxFileBytes>>20)
	}
	job := &parseJob{dirs: []string{root}, files: 1, bytes: int64(len(src))}
	if real, err := filepath.EvalSymlinks(root); err == nil && real != root {
		job.dirs = append(job.dirs, real)
	}
	p := &parser{file: "config", src: src, line: 1, root: root, job: job, warnings: warnings}
	ds, err := p.parseBlock(true)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %v", p.file, p.line, err)
	}
	return ds, nil
}

func inside(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (j *parseJob) allowed(path string) bool {
	for _, d := range j.dirs {
		if inside(d, path) {
			return true
		}
	}
	return false
}

// readConfig reads one config file within the job's limits.
func (j *parseJob) readConfig(path string) ([]byte, error) {
	if j.files++; j.files > maxFiles {
		return nil, fmt.Errorf("more than %d files (include loop?)", maxFiles)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", clean(path))
	}
	src, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(src) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d MB", clean(path), maxFileBytes>>20)
	}
	if j.bytes += int64(len(src)); j.bytes > maxConfigBytes {
		return nil, fmt.Errorf("config and its includes are larger than %d MB in total", maxConfigBytes>>20)
	}
	return src, nil
}

func parseFile(path, root string, depth, nest int, job *parseJob, warnings *[]string) ([]*Directive, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("%s: include depth exceeds %d (include cycle?)", clean(path), maxIncludeDepth)
	}
	src, err := job.readConfig(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		rel = path
	}
	p := &parser{file: clean(filepath.ToSlash(rel)), src: src, line: 1, root: root, depth: depth, nest: nest, job: job, warnings: warnings}
	ds, err := p.parseBlock(true)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %v", p.file, p.line, err)
	}
	return ds, nil
}

func (p *parser) warn(format string, a ...any) {
	if len(*p.warnings) >= 200 {
		if len(*p.warnings) == 200 {
			*p.warnings = append(*p.warnings, "further warnings are not shown")
		}
		return
	}
	*p.warnings = append(*p.warnings, clean(fmt.Sprintf("%s:%d: ", p.file, p.line)+fmt.Sprintf(format, a...)))
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
		if p.job.directives++; p.job.directives > maxDirectives {
			return nil, fmt.Errorf("more than %d directives", maxDirectives)
		}
		d := &Directive{Name: t.val, NQ: t.quoted, File: p.file, Line: t.line}
		for {
			a, ok, err := p.next()
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("unexpected end of file in directive %q (missing \";\"?)", clean(d.Name))
			}
			if !a.quoted && a.val == ";" {
				break
			}
			if !a.quoted && a.val == "}" {
				return nil, fmt.Errorf("unexpected \"}\" in directive %q (missing \";\"?)", clean(d.Name))
			}
			if !a.quoted && a.val == "{" {
				d.IsBlk = true
				if strings.HasSuffix(d.Name, "_by_lua_block") {
					if err := p.skipRawBlock(); err != nil {
						return nil, err
					}
					break
				}
				if p.nest++; p.nest > maxBlockDepth {
					return nil, fmt.Errorf("blocks nested more than %d deep", maxBlockDepth)
				}
				kids, err := p.parseBlock(false)
				if err != nil {
					return nil, err
				}
				p.nest--
				d.Block = kids
				break
			}
			if len(d.Args) >= maxArgs {
				return nil, fmt.Errorf("directive %q has more than %d arguments (missing \";\"?)", clean(d.Name), maxArgs)
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

// globMeta reports whether a path contains glob syntax.
func globMeta(s string) bool {
	if filepath.Separator == '\\' {
		return strings.ContainsAny(s, "*?[")
	}
	return strings.ContainsAny(s, "*?[\\")
}

func (p *parser) include(pattern string) ([]*Directive, error) {
	if strings.IndexByte(pattern, 0) >= 0 {
		p.warn("include with a NUL byte in its path (skipped)")
		return nil, nil
	}
	full := pattern
	if !filepath.IsAbs(full) {
		full = filepath.Join(p.root, full)
	}
	full = filepath.Clean(full)
	// The fixed leading part of the pattern must already be inside an allowed
	// directory, so that a pattern cannot be used to walk the file system.
	fixed := full
	for globMeta(fixed) {
		fixed = filepath.Dir(fixed)
	}
	if !p.job.allowed(fixed) {
		p.warn("include %q is outside the directory of the config (skipped; allow it with -include-dir)", pattern)
		return nil, nil
	}
	matches, err := filepath.Glob(full)
	if err != nil {
		return nil, fmt.Errorf("bad include pattern %q: %v", clean(pattern), err)
	}
	if len(matches) == 0 {
		// nginx tolerates empty globs; a missing literal file is an error
		// there, but for analysis we warn and continue.
		p.warn("include %q matched no files (skipped)", pattern)
		return nil, nil
	}
	if len(matches) > maxFiles {
		return nil, fmt.Errorf("include %q matches more than %d files", clean(pattern), maxFiles)
	}
	sort.Strings(matches)
	var out []*Directive
	for _, m := range matches {
		// What the path really is, after symbolic links, decides.
		real, err := filepath.EvalSymlinks(m)
		if err != nil {
			p.warn("include %q: cannot resolve %q (skipped)", pattern, m)
			continue
		}
		st, err := os.Stat(real)
		if err != nil || !st.Mode().IsRegular() {
			if err == nil && st.IsDir() && globMeta(full) {
				continue // a glob that also matched a directory, as in nginx
			}
			p.warn("include %q: %q is not a regular file (skipped)", pattern, m)
			continue
		}
		if !p.job.allowed(real) {
			p.warn("include %q: %q leads outside the directory of the config (skipped; allow it with -include-dir)", pattern, m)
			continue
		}
		ds, err := parseFile(m, p.root, p.depth+1, p.nest, p.job, p.warnings)
		if err != nil {
			return nil, err
		}
		out = append(out, ds...)
	}
	return out, nil
}
