package main

// Verify mode: run a scratch copy of every config under a real nginx binary,
// send test requests through it, and record what nginx actually did
// (locations chosen per hop, final status, request that reached a backend).
// The HTML viewer compares these observations with its own simulation.
//
// Everything binds to 127.0.0.1 on free ports. Backends that have no config
// are replaced by local stubs, so no request leaves the machine.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type StubReq struct {
	Addr   string `json:"addr"` // original backend address this stub stands in for
	Method string `json:"method"`
	URI    string `json:"uri"`
	Host   string `json:"host"`
}

type VCase struct {
	Method   string     `json:"method"`
	URL      string     `json:"url"`
	Headers  []string   `json:"headers"`
	Error    string     `json:"error,omitempty"`
	Status   int        `json:"status"`
	Location string     `json:"location,omitempty"`
	Locs     [][]string `json:"locs"` // per hop: locations nginx reported, in order
	Stub     *StubReq   `json:"stub,omitempty"`
}

type Verify struct {
	Nginx string   `json:"nginx"`
	Debug bool     `json:"debug"`
	Cases []*VCase `json:"cases"`
	Notes []string `json:"notes"`
}

type shop struct {
	hop   *Hop
	ports map[int]int  // original listen port -> scratch port
	ssl   map[int]bool // original listen port -> uses TLS
	ups   map[string][]string
	dir   string
	cmd   *exec.Cmd
	off   int64
}

type scratch struct {
	b         *Bundle
	dir       string
	hops      []*shop
	stubs     map[string]int // original backend addr -> stub port
	closed    int            // a port nothing listens on
	certFile  string
	keyFile   string
	tlsCfg    *tls.Config
	roots     *x509.CertPool  // trusts the scratch certificate and nothing else
	certNames map[string]bool // names the scratch certificate is valid for
	notes     map[string]bool
	allow     map[string]bool // extra directive names the user allowed (-verify-allow)
	dropped   map[string]bool // directive names left out of the scratch configs
	mu        sync.Mutex
	reqs      []StubReq
	lns       []net.Listener
	newStub   func(addr string) (int, error) // tests replace the real listener
}

func (s *scratch) note(format string, a ...any) { s.notes[fmt.Sprintf(format, a...)] = true }

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func listenPortOf(d *Directive) (int, bool) {
	a := "80"
	if len(d.Args) > 0 {
		a = d.Args[0]
	}
	if strings.HasPrefix(a, "unix:") {
		return 0, false
	}
	if n, err := strconv.Atoi(a); err == nil {
		return n, n >= 1 && n <= 65535
	}
	if i := strings.LastIndexByte(a, ':'); i >= 0 {
		if n, err := strconv.Atoi(a[i+1:]); err == nil {
			return n, n >= 1 && n <= 65535
		}
	}
	return 80, true
}

func hasArg(d *Directive, v string) bool {
	for _, a := range d.Args[min(1, len(d.Args)):] {
		if a == v {
			return true
		}
	}
	return false
}

// ---- self-signed certificate for TLS listeners and stubs ----

// scratchName is always a name on the scratch certificate.
const scratchName = "nginxviz-scratch"

var reDNSName = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)

// certName returns host if the scratch certificate can carry it as a name.
func certName(host string) (string, bool) {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return host, true
	}
	return host, len(host) <= 253 && reDNSName.MatchString(host)
}

// makeCert creates the throwaway certificate used by scratch TLS listeners
// and stubs. It is valid for the host names of the requests to be replayed
// (at most maxCertNames of them), so that the client can verify it properly
// instead of switching certificate checks off.
func (s *scratch) makeCert(hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nginxviz-scratch"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{scratchName},
	}
	s.certNames = map[string]bool{scratchName: true}
	for _, h := range hosts {
		h, ok := certName(h)
		if !ok || s.certNames[h] || len(s.certNames) >= maxCertNames {
			continue
		}
		s.certNames[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	s.certFile, s.keyFile = filepath.Join(s.dir, "cert.pem"), filepath.Join(s.dir, "key.pem")
	if err := os.WriteFile(s.certFile, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(s.keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	s.roots = x509.NewCertPool()
	s.roots.AddCert(leaf)
	return nil
}

// ---- backend stubs (plain HTTP or TLS, detected per connection) ----

type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
}

func (c *chanListener) Accept() (net.Conn, error) {
	select {
	case conn := <-c.ch:
		return conn, nil
	case <-c.done:
		return nil, net.ErrClosed
	}
}
func (c *chanListener) Close() error   { return nil }
func (c *chanListener) Addr() net.Addr { return c.addr }

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (s *scratch) stubFor(addr string) (int, error) {
	if p, ok := s.stubs[addr]; ok {
		return p, nil
	}
	if len(s.stubs) >= maxStubs {
		return 0, fmt.Errorf("more than %d different backend addresses to stub", maxStubs)
	}
	if s.newStub != nil {
		p, err := s.newStub(addr)
		if err == nil {
			s.stubs[addr] = p
		}
		return p, err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	s.lns = append(s.lns, l)
	cl := &chanListener{ch: make(chan net.Conn), addr: l.Addr(), done: make(chan struct{})}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				close(cl.done)
				return
			}
			go func() {
				br := bufio.NewReader(conn)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				first, err := br.Peek(1)
				conn.SetReadDeadline(time.Time{})
				if err != nil {
					conn.Close()
					return
				}
				var c net.Conn = &peekConn{Conn: conn, r: br}
				if first[0] == 0x16 { // TLS handshake
					c = tls.Server(c, s.tlsCfg)
				}
				select {
				case cl.ch <- c:
				case <-cl.done:
					conn.Close()
				}
			}()
		}
	}()
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, StubReq{Addr: addr, Method: r.Method, URI: r.RequestURI, Host: r.Host})
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "nginxviz stub for "+addr+"\n")
	})}
	go srv.Serve(cl)
	p := l.Addr().(*net.TCPAddr).Port
	s.stubs[addr] = p
	return p, nil
}

// ---- config rewriting ----

func dropDirective(name string) bool {
	switch name {
	case "user", "pid", "daemon", "master_process", "error_log", "access_log", "lock_file",
		"stream", "mail", "proxy_cache", "fastcgi_cache", "uwsgi_cache", "scgi_cache":
		return true
	}
	return strings.HasPrefix(name, "ssl_") || strings.HasPrefix(name, "proxy_ssl_") ||
		strings.HasSuffix(name, "_temp_path") || strings.HasSuffix(name, "_cache_path")
}

// verifyAllowed lists the directives that are copied into a scratch config.
// A scratch config is run by a real nginx, so a config from an untrusted
// source must not be able to make that nginx do anything but route requests
// on 127.0.0.1: no loading code (load_module, perl, njs, Lua), no writing
// files (proxy_store, dav, logs, temp and cache paths), no network use
// (resolver, syslog), no sizing of memory. Everything not listed here is left
// out and reported; -verify-allow adds names for one run.
var verifyAllowed = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`
		http server location upstream if limit_except map geo split_clients types charset_map
		listen server_name root alias index try_files error_page internal return rewrite set break
		allow deny satisfy auth_basic auth_basic_user_file auth_request auth_request_set
		real_ip_header set_real_ip_from real_ip_recursive valid_referers
		proxy_pass proxy_set_header proxy_redirect proxy_http_version proxy_method
		proxy_pass_request_headers proxy_pass_request_body proxy_intercept_errors
		proxy_hide_header proxy_pass_header proxy_set_body proxy_cookie_domain proxy_cookie_path
		proxy_next_upstream proxy_next_upstream_tries proxy_buffering proxy_request_buffering
		proxy_ignore_headers proxy_connect_timeout proxy_read_timeout proxy_send_timeout
		fastcgi_pass fastcgi_param fastcgi_index fastcgi_split_path_info fastcgi_intercept_errors
		uwsgi_pass uwsgi_param scgi_pass scgi_param grpc_pass grpc_set_header memcached_pass
		least_conn ip_hash hash random keepalive keepalive_requests keepalive_timeout
		add_header expires default_type charset etag if_modified_since autoindex
		merge_slashes absolute_redirect port_in_redirect server_name_in_redirect
		recursive_error_pages underscores_in_headers ignore_invalid_headers
		client_max_body_size server_tokens sendfile tcp_nopush tcp_nodelay
		gzip gzip_types gzip_vary gzip_proxied gzip_comp_level gzip_min_length
		log_not_found log_subrequest rewrite_log uninitialized_variable_warn
		mirror mirror_request_body stub_status empty_gif http2 disable_symlinks`) {
		verifyAllowed[n] = true
	}
}

// keep reports whether directive name may go into a scratch config.
func (s *scratch) keep(name string) bool {
	if verifyAllowed[name] || s.allow[name] {
		return true
	}
	if s.dropped == nil {
		s.dropped = map[string]bool{}
	}
	if len(s.dropped) < 200 {
		s.dropped[name] = true
	}
	return false
}

// dataBlocks hold key/value data, not directives; they are copied untouched.
var dataBlocks = map[string]bool{"map": true, "types": true, "geo": true, "split_clients": true, "charset_map": true}

func mk(name string, args ...string) *Directive { return &Directive{Name: name, Args: args} }

// target maps an original backend address to its scratch replacement.
func (s *scratch) target(addr string, defPort int) (string, error) {
	addr = strings.ToLower(addr)
	if h := resolveHop(s.b, []string{addr}); h != nil {
		var sh *shop
		for _, x := range s.hops {
			if x.hop == h {
				sh = x
			}
		}
		port := defPort
		if i := strings.LastIndexByte(addr, ':'); i > 0 && !strings.HasSuffix(addr, "]") {
			if n, err := strconv.Atoi(addr[i+1:]); err == nil {
				port = n
			}
		}
		sp, ok := sh.ports[port]
		if !ok {
			var ps []int
			for p := range sh.ports {
				ps = append(ps, p)
			}
			sort.Ints(ps)
			sp = sh.ports[ps[0]]
			s.note("%s is mapped to hop %q, which does not listen on port %d; its port %d listener is used instead.", addr, h.Name, port, ps[0])
		}
		return "127.0.0.1:" + strconv.Itoa(sp), nil
	}
	p, err := s.stubFor(addr)
	if err != nil {
		return "", err
	}
	return "127.0.0.1:" + strconv.Itoa(p), nil
}

// reBackendHost is what a literal proxy_pass host may look like: a name or
// IPv4 address, or an IPv6 address in brackets, with an optional port.
var reBackendHost = regexp.MustCompile(`^([a-z0-9._-]+|\[[0-9a-f:.]+\])(:[0-9]{1,5})?$`)

var passRe = regexp.MustCompile(`^(?:([a-z]+)://)?([^/?]+)(.*)$`)

func (s *scratch) xform(h *shop, ds []*Directive, stack [][]*Directive, ctx string) ([]*Directive, error) {
	var out []*Directive
	type lst struct{ ssl, def bool }
	listens := map[int]*lst{}
	if ctx == "server" {
		for _, d := range ds {
			if d.Name == "listen" {
				if p, ok := listenPortOf(d); ok {
					if listens[p] == nil {
						listens[p] = &lst{}
					}
					listens[p].ssl = listens[p].ssl || hasArg(d, "ssl")
					listens[p].def = listens[p].def || hasArg(d, "default_server") || hasArg(d, "default")
				}
			}
		}
		if len(find(ds, "listen")) == 0 {
			out = append(out, mk("listen", "127.0.0.1:"+strconv.Itoa(h.ports[80])))
		}
	}
	emitted := map[int]bool{}
	injectHost := ""
	for _, d := range ds {
		if strings.Contains(d.Name, "_by_lua") {
			return nil, fmt.Errorf("%s:%d: %s cannot be reproduced in a scratch config; verify does not support Lua", d.File, d.Line, clean(d.Name))
		}
		if dropDirective(d.Name) || !s.keep(d.Name) {
			continue
		}
		// Directives that name an address are always rewritten below; one
		// that is malformed or misplaced is left out, never copied as written.
		switch {
		case d.Name == "listen" && ctx != "server",
			d.Name == "server" && ctx == "upstream" && (len(d.Args) == 0 || d.IsBlk),
			strings.HasSuffix(d.Name, "_pass") && (len(d.Args) == 0 || d.IsBlk):
			continue
		}
		c := *d
		switch {
		case d.Name == "listen" && ctx == "server":
			p, ok := listenPortOf(d)
			if !ok || emitted[p] {
				continue
			}
			emitted[p] = true
			args := []string{"127.0.0.1:" + strconv.Itoa(h.ports[p])}
			if listens[p].ssl {
				args = append(args, "ssl")
			}
			if listens[p].def {
				args = append(args, "default_server")
			}
			c.Args, c.Q = args, nil
		case d.Name == "server" && ctx == "upstream" && len(d.Args) > 0:
			t, err := s.target(d.Args[0], 80)
			if err != nil {
				return nil, err
			}
			args := []string{t}
			for _, a := range d.Args[1:] {
				if a != "resolve" && !strings.HasPrefix(a, "service=") {
					args = append(args, a)
				}
			}
			c.Args, c.Q = args, nil
		case d.Name == "proxy_pass" && len(d.Args) > 0:
			m := passRe.FindStringSubmatch(d.Args[0])
			if m == nil { // nothing nginx would accept; never pass it through as written
				c.Args, c.Q = []string{"http://127.0.0.1:" + strconv.Itoa(s.closed)}, nil
				break
			}
			scheme, host, rest := m[1], strings.ToLower(m[2]), m[3]
			if scheme == "" {
				scheme = "http"
			}
			if strings.HasPrefix(host, "unix:") {
				// http://unix:/path/to.sock:/uri
				full := d.Args[0][strings.Index(d.Args[0], "unix:"):]
				end := strings.IndexByte(full[5:], ':')
				sock, uri := full, ""
				if end >= 0 {
					sock, uri = full[:5+end], full[5+end+1:]
				}
				t, err := s.target(sock, 80)
				if err != nil {
					return nil, err
				}
				c.Args, c.Q = []string{scheme + "://" + t + uri}, nil
				injectHost = "localhost"
				break
			}
			if !strings.Contains(host, "$") && !reBackendHost.MatchString(host) {
				// not a host nginx would accept; never pass it through as written
				s.note("%s:%d: proxy_pass target is not a plain host[:port]; requests reaching it are not verifiable.", d.File, d.Line)
				c.Args, c.Q = []string{"http://127.0.0.1:" + strconv.Itoa(s.closed)}, nil
				break
			}
			if strings.Contains(host, "$") {
				s.note("%s:%d: proxy_pass host contains variables and cannot be redirected to a scratch target; requests reaching it are not verifiable.", d.File, d.Line)
				c.Args, c.Q = []string{"http://127.0.0.1:" + strconv.Itoa(s.closed)}, nil
				break
			}
			if _, isUp := h.ups[host]; isUp {
				break
			}
			def := 80
			if scheme == "https" {
				def = 443
			}
			t, err := s.target(host, def)
			if err != nil {
				return nil, err
			}
			c.Args, c.Q = []string{scheme + "://" + t + rest}, nil
			injectHost = m[2]
		case d.Name == "grpc_pass":
			c.Args, c.Q = []string{"grpc://127.0.0.1:" + strconv.Itoa(s.closed)}, nil
			s.note("grpc_pass targets are not stubbed; only the location choice is verified for requests reaching them.")
		case d.Name == "fastcgi_pass" || d.Name == "uwsgi_pass" || d.Name == "scgi_pass" || d.Name == "memcached_pass":
			c.Args, c.Q = []string{"127.0.0.1:" + strconv.Itoa(s.closed)}, nil
			s.note("%s backends are not stubbed (nginx answers 502 in the scratch run); only the location choice is verified for requests reaching them.", d.Name)
		}
		if d.IsBlk {
			if !dataBlocks[d.Name] {
				kids, err := s.xform(h, d.Block, append(stack, ds), d.Name)
				if err != nil {
					return nil, err
				}
				c.Block = kids
			}
		}
		out = append(out, &c)
	}
	// The scratch address must not leak into the Host header the next server
	// sees: where nginx would have sent the original host by default, pin it.
	if injectHost != "" {
		own := find(ds, "proxy_set_header")
		eff := own
		for i := len(stack) - 1; i >= 0 && len(eff) == 0; i-- {
			eff = find(stack[i], "proxy_set_header")
		}
		hasHost := false
		for _, e := range eff {
			if len(e.Args) > 0 && strings.EqualFold(e.Args[0], "host") {
				hasHost = true
			}
		}
		if !hasHost {
			if len(own) == 0 {
				for _, e := range eff {
					cp := *e
					out = append(out, &cp)
				}
			}
			out = append(out, mk("proxy_set_header", "Host", injectHost))
		}
	}
	return out, nil
}

func quoteArg(a string, quoted bool) string {
	if !quoted && a != "" && !strings.ContainsAny(a, " \t\r\n;{}\"'#") {
		return a
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a) + `"`
}

func serialize(sb *strings.Builder, ds []*Directive, ind int) {
	for _, d := range ds {
		sb.WriteString(strings.Repeat("    ", ind))
		sb.WriteString(quoteArg(d.Name, d.NQ))
		for i, a := range d.Args {
			sb.WriteByte(' ')
			sb.WriteString(quoteArg(a, i < len(d.Q) && d.Q[i]))
		}
		if d.IsBlk {
			sb.WriteString(" {\n")
			serialize(sb, d.Block, ind+1)
			sb.WriteString(strings.Repeat("    ", ind) + "}\n")
		} else {
			sb.WriteString(";\n")
		}
	}
}

func (s *scratch) buildConf(h *shop) (string, error) {
	tree := h.hop.Tree
	if len(find(tree, "http")) == 0 { // fragment: bare server or location blocks
		inner := tree
		if len(find(tree, "server")) == 0 {
			inner = []*Directive{{Name: "server", IsBlk: true, Block: tree}}
		}
		tree = []*Directive{{Name: "http", IsBlk: true, Block: inner}}
	}
	top, err := s.xform(h, tree, nil, "main")
	if err != nil {
		return "", err
	}
	anySSL := false
	for _, v := range h.ssl {
		anySSL = anySSL || v
	}
	for _, d := range top {
		if d.Name != "http" {
			continue
		}
		pre := []*Directive{mk("access_log", "off"), mk("server_names_hash_bucket_size", "128"), mk("map_hash_bucket_size", "128")}
		for _, n := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
			pre = append(pre, mk(n+"_temp_path", filepath.Join(h.dir, "tmp-"+n)))
		}
		if anySSL {
			pre = append(pre, mk("ssl_certificate", s.certFile), mk("ssl_certificate_key", s.keyFile))
		}
		d.Block = append(pre, d.Block...)
	}
	pre := []*Directive{mk("daemon", "off"), mk("master_process", "off"),
		mk("pid", filepath.Join(h.dir, "nginx.pid")), mk("error_log", filepath.Join(h.dir, "error.log"), "debug")}
	pre = append(pre, &Directive{Name: "events", IsBlk: true, Block: []*Directive{mk("worker_connections", "256")}})
	var sb strings.Builder
	sb.WriteString("# scratch config generated by nginxviz verify - not for production\n")
	serialize(&sb, append(pre, top...), 0)
	return sb.String(), nil
}

// plan gives every hop a scratch directory and a scratch port (from alloc)
// for each port its servers listen on.
func (s *scratch) plan(alloc func() (int, error)) error {
	for i, hop := range s.b.Hops {
		h := &shop{hop: hop, ports: map[int]int{}, ssl: map[int]bool{}, ups: upstreams(hop.Tree), dir: filepath.Join(s.dir, fmt.Sprintf("hop%d", i))}
		if err := os.MkdirAll(h.dir, 0o700); err != nil {
			return err
		}
		add := func(p int, ssl bool) error {
			if _, ok := h.ports[p]; !ok {
				if len(h.ports) >= maxListenPorts {
					return fmt.Errorf("%s: more than %d different listen ports", clean(hop.File), maxListenPorts)
				}
				fp, err := alloc()
				if err != nil {
					return err
				}
				h.ports[p] = fp
			}
			h.ssl[p] = h.ssl[p] || ssl
			return nil
		}
		srvs := serverBlocks(hop.Tree)
		if len(srvs) == 0 {
			return fmt.Errorf("%s: no server blocks to verify", clean(hop.File))
		}
		for _, sv := range srvs {
			ls := find(sv.Block, "listen")
			if len(ls) == 0 {
				if err := add(80, false); err != nil {
					return err
				}
			}
			for _, l := range ls {
				if p, ok := listenPortOf(l); ok {
					if err := add(p, hasArg(l, "ssl")); err != nil {
						return err
					}
				}
			}
		}
		if len(h.ports) == 0 {
			return fmt.Errorf("%s: no TCP listen directives to verify", clean(hop.File))
		}
		s.hops = append(s.hops, h)
	}
	return nil
}

// ---- running ----

var (
	reConf  = regexp.MustCompile(`using configuration "(.*)"`)
	reNamed = regexp.MustCompile(`using location: (@\S+)`)
)

func (h *shop) newLocs() []string {
	f, err := os.Open(filepath.Join(h.dir, "error.log"))
	if err != nil {
		return nil
	}
	defer f.Close()
	f.Seek(h.off, io.SeekStart)
	data, _ := io.ReadAll(io.LimitReader(f, maxLogBytes))
	h.off += int64(len(data))
	type hit struct {
		pos int
		v   string
	}
	var hits []hit
	for _, m := range reConf.FindAllSubmatchIndex(data, -1) {
		hits = append(hits, hit{m[0], string(data[m[2]:m[3]])})
	}
	for _, m := range reNamed.FindAllSubmatchIndex(data, -1) {
		hits = append(hits, hit{m[0], string(data[m[2]:m[3]])})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })
	out := []string{}
	for _, x := range hits {
		out = append(out, x.v)
	}
	return out
}

func readCases(path string) ([]*VCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCasesBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCasesBytes {
		return nil, fmt.Errorf("%s is larger than %d MB", path, maxCasesBytes>>20)
	}
	return parseCases(data, path)
}

func parseCases(data []byte, path string) ([]*VCase, error) {
	var out []*VCase
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if len(line) > maxCaseLine {
			return nil, fmt.Errorf("%s: a line is longer than %d bytes", path, maxCaseLine)
		}
		if len(out) >= maxCases {
			return nil, fmt.Errorf("%s: more than %d requests", path, maxCases)
		}
		parts := strings.Split(line, " | ")
		c := &VCase{Method: "GET", Headers: []string{}}
		f := strings.Fields(parts[0])
		switch len(f) {
		case 1:
			c.URL = f[0]
		case 2:
			c.Method, c.URL = strings.ToUpper(f[0]), f[1]
		default:
			return nil, fmt.Errorf("%s: cannot parse line %q (want: [METHOD] URL [ | Header: value]...)", path, clean(line))
		}
		if !strings.Contains(c.URL, "://") {
			c.URL = "http://" + c.URL
		}
		for _, hd := range parts[1:] {
			if strings.Contains(hd, ":") {
				c.Headers = append(c.Headers, strings.TrimSpace(hd))
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no URLs found", path)
	}
	return out, nil
}

// RunVerify executes all cases against scratch nginx instances.
func RunVerify(b *Bundle, nginxBin, casesPath string, keep bool, allow []string) (*Verify, error) {
	cases, err := readCases(casesPath)
	if err != nil {
		return nil, err
	}
	bin, err := exec.LookPath(nginxBin)
	if err != nil {
		return nil, fmt.Errorf("nginx binary %q not found (use -nginx /path/to/nginx)", nginxBin)
	}
	vout, _ := exec.Command(bin, "-V").CombinedOutput()
	v := &Verify{Nginx: strings.TrimPrefix(strings.SplitN(string(vout), "\n", 2)[0], "nginx version: "),
		Debug: bytes.Contains(vout, []byte("--with-debug")), Notes: []string{}}

	dir, err := os.MkdirTemp("", "nginxviz-verify-")
	if err != nil {
		return nil, err
	}
	s := &scratch{b: b, dir: dir, stubs: map[string]int{}, notes: map[string]bool{}, allow: map[string]bool{}}
	for _, a := range allow {
		s.allow[a] = true
	}
	defer func() {
		for _, h := range s.hops {
			if h.cmd != nil && h.cmd.Process != nil {
				h.cmd.Process.Kill()
				h.cmd.Wait()
			}
		}
		for _, l := range s.lns {
			l.Close()
		}
		if keep {
			fmt.Fprintln(os.Stderr, "scratch directory kept:", dir)
		} else {
			os.RemoveAll(dir)
		}
	}()
	var hosts []string
	for _, c := range cases {
		if u, err := url.Parse(c.URL); err == nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	if err := s.makeCert(hosts); err != nil {
		return nil, err
	}
	if s.closed, err = freePort(); err != nil {
		return nil, err
	}
	if err := s.plan(freePort); err != nil {
		return nil, err
	}
	// pass 2: write configs, check them, start nginx
	for _, h := range s.hops {
		conf, err := s.buildConf(h)
		if err != nil {
			return nil, err
		}
		cf := filepath.Join(h.dir, "nginx.conf")
		if err := os.WriteFile(cf, []byte(conf), 0o600); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, bin, "-t", "-c", cf, "-p", h.dir).CombinedOutput()
		cancel()
		if err != nil {
			keep = true
			return nil, fmt.Errorf("nginx rejected the scratch config for hop %q:\n%s%s", h.hop.Name, out, s.droppedNote())
		}
		h.cmd = exec.Command(bin, "-c", cf, "-p", h.dir)
		if err := h.cmd.Start(); err != nil {
			return nil, err
		}
	}
	for _, h := range s.hops {
		for _, sp := range h.ports {
			ok := false
			for i := 0; i < 100 && !ok; i++ {
				if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(sp), 200*time.Millisecond); err == nil {
					c.Close()
					ok = true
				} else {
					time.Sleep(50 * time.Millisecond)
				}
			}
			if !ok {
				return nil, fmt.Errorf("scratch nginx for hop %q did not start listening", h.hop.Name)
			}
		}
		h.newLocs() // skip startup noise
	}
	if !v.Debug {
		s.note("This nginx binary was built without --with-debug, so the locations it chose are not visible. Only final status, redirects and backend requests are verified.")
	}

	entry := s.hops[0]
	for _, c := range cases {
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" {
			c.Error = "not a valid URL"
			continue
		}
		port := 80
		if u.Scheme == "https" {
			port = 443
		}
		if u.Port() != "" {
			port, _ = strconv.Atoi(u.Port())
		}
		sp, ok := entry.ports[port]
		if !ok {
			c.Error = fmt.Sprintf("no server in %q listens on port %d", entry.hop.Name, port)
			continue
		}
		scheme := "http"
		if entry.ssl[port] {
			scheme = "https"
		}
		req, err := http.NewRequest(c.Method, scheme+"://127.0.0.1:"+strconv.Itoa(sp)+u.RequestURI(), nil)
		if err != nil {
			c.Error = err.Error()
			continue
		}
		req.Host = u.Host
		for _, hd := range c.Headers {
			i := strings.IndexByte(hd, ':')
			k, val := strings.TrimSpace(hd[:i]), strings.TrimSpace(hd[i+1:])
			if strings.EqualFold(k, "host") {
				req.Host = val
			} else {
				req.Header.Set(k, val)
			}
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "nginxviz-verify")
		}
		// The scratch certificate is the only one trusted. The server name
		// (SNI) is the request's host where the certificate carries it.
		sni := scratchName
		if n, ok := certName(u.Hostname()); ok && s.certNames[n] {
			sni = n
		}
		client := &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{RootCAs: s.roots, ServerName: sni, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		s.mu.Lock()
		s.reqs = nil
		s.mu.Unlock()
		resp, err := client.Do(req)
		if err != nil {
			c.Error = "no response: " + err.Error()
		} else {
			io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
			resp.Body.Close()
			c.Status = resp.StatusCode
			c.Location = s.normLocation(resp.Header.Get("Location"))
		}
		time.Sleep(20 * time.Millisecond)
		for _, h := range s.hops {
			locs := h.newLocs()
			if !v.Debug {
				locs = nil
			}
			c.Locs = append(c.Locs, locs)
		}
		s.mu.Lock()
		if n := len(s.reqs); n > 0 {
			r := s.reqs[n-1]
			c.Stub = &r
		}
		s.mu.Unlock()
	}
	v.Cases = cases
	if n := s.droppedNote(); n != "" {
		s.note("%s", strings.TrimSpace(n))
	}
	for n := range s.notes {
		v.Notes = append(v.Notes, n)
	}
	sort.Strings(v.Notes)
	return v, nil
}

// droppedNote lists the directives that were left out of the scratch configs.
func (s *scratch) droppedNote() string {
	if len(s.dropped) == 0 {
		return ""
	}
	var names []string
	for n := range s.dropped {
		names = append(names, clean(n))
	}
	sort.Strings(names)
	more := ""
	if len(names) > 40 {
		more = fmt.Sprintf(" and %d more", len(names)-40)
		names = names[:40]
	}
	return "\nNot copied into the scratch configs, because they are not on the list of directives known to be safe to run: " +
		strings.Join(names, ", ") + more + ". Their effect is not verified. To include one, use -verify-allow NAME."
}

// normLocation maps scratch ports in a redirect back to the original ports.
func (s *scratch) normLocation(loc string) string {
	if loc == "" {
		return ""
	}
	for _, h := range s.hops {
		for orig, sp := range h.ports {
			loc = strings.Replace(loc, ":"+strconv.Itoa(sp), ":"+strconv.Itoa(orig), 1)
		}
	}
	if strings.HasPrefix(loc, "http://") {
		loc = strings.Replace(loc, ":80/", "/", 1)
	} else if strings.HasPrefix(loc, "https://") {
		loc = strings.Replace(loc, ":443/", "/", 1)
	}
	return loc
}
