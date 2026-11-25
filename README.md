# nginxviz

Turns one or more nginx configurations into:

- `nginx-flow.html` — a single self-contained interactive page. Enter a URL and
  step it through server selection, rewrites, `if`, location matching, access
  rules, `try_files`, `error_page` and `proxy_pass`, across several nginx
  instances.
- `nginx-flow.md` — a Mermaid flowchart / decision tree of the same configs.

## Build

    go build -o nginxviz .

Go standard library only: no modules to download, no `go.sum`.

## Test

    go test ./...
    go test -run '^$' -fuzz FuzzParse -fuzztime 30s .   # optional: fuzz the config parser

The tests need no nginx. They cover the config parser, the Mermaid output
(`examples/out/nginx-flow.md` is the expected output for the example configs),
and the config rewriting done by `-verify`. They do not start nginx, and they
do not run the page's JavaScript simulator: that is checked by `-verify`.

## Use

    nginxviz [flags] [name=]nginx.conf [[name=]other.conf ...]

The first config is the entry point. Use `-addr name=host[:port]` to say which
addresses (as they appear in `proxy_pass` / `upstream` blocks) reach which
config, so the trace can follow the request from one instance to the next:

    nginxviz -o out \
      -addr app=10.0.0.5:8080 -addr api=api.internal:9000 \
      edge=examples/edge/nginx.conf app=examples/app/nginx.conf api=examples/api/nginx.conf

`include` directives (with globs) are followed, relative to the directory of
the top-level config file. Fragments (bare `server` or `location` blocks) work.

## Verify against real nginx (optional)

The page's simulator is a re-implementation of nginx's rules. To check it
against nginx itself, give `-verify` a file of URLs:

    nginxviz -verify examples/urls.txt -nginx /usr/sbin/nginx -o out [-addr ...] edge=... app=... api=...

    # urls.txt: one request per line
    https://example.com/api/v1/posts/42?x=1
    POST https://example.com/blog/x | User-Agent: Googlebot | Cookie: a=b

What happens:

1. A scratch copy of each config is written to a temp directory: listen
   addresses become free ports on 127.0.0.1, log/pid/temp/cache paths move into
   the temp directory, TLS uses a throwaway self-signed certificate, and
   `proxy_pass`/`upstream` targets point at the other scratch instances or at
   local stub backends. Your real config files are never modified.
2. One nginx process per config is started, each request is sent, and nginx's
   debug log is read for the locations it chose. Stubs record the request
   that reached each backend. Everything is then stopped and deleted
   (`-keep` keeps the directory for inspection).
3. The observations are embedded in the HTML. The page runs its own
   simulation of each request and lists, per URL, whether nginx and the
   simulation agree on: locations chosen in every hop, final status, redirect
   target, and the request line and Host header sent to the backend.

Nothing is sent off the machine: all listeners and stubs are on 127.0.0.1.
nginx is needed only for `-verify`; the tool and the HTML work without it.

Limits of verify:

- Requests come from 127.0.0.1, so `allow`/`deny` are evaluated for that address.
- Use the same nginx version and modules as production. Location checks need a
  binary built `--with-debug` (most distribution packages are); without it only
  status, redirects and backend requests are compared.
- `ssl_*`, `proxy_ssl_*`, cache and log directives are removed from the scratch
  copy, so client-certificate checks and caching are not exercised.
- FastCGI/uwsgi/SCGI/gRPC backends are not stubbed; for requests that end
  there, only the location choice is compared.
- Static files are looked up on the machine running verify, so their status
  reflects that machine's disk.
- `$server_port` shows the scratch port. `proxy_pass` with variables in the
  host, and Lua blocks, are not supported.
- If nginx rejects the scratch config (for example a missing module or file),
  the error is printed and the scratch directory is kept.

## Security properties

- The binary only reads the config files you name (and their includes) and
  writes two output files. Without `-verify` it makes no network connections;
  with `-verify` it uses 127.0.0.1 only and starts the nginx binary you name.
- The HTML has no external scripts, styles, fonts or images, and carries a
  Content-Security-Policy of `default-src 'none'`, so the browser will not
  make any request from it. Nothing is stored in the browser.
- Config text is inserted into the page as text nodes only, never as HTML.
- Note the outputs contain your full configuration text; handle them like the
  configs themselves.

## What the simulator models, and what it assumes

Modelled: `listen`/`server_name` selection (exact, wildcard, regex, default),
`location` matching (`=`, `^~`, `~`, `~*`, prefix, nested, named), `rewrite`
(`last`/`break`/`redirect`/`permanent`), `return`, `set`, `if`, `map`,
`allow`/`deny` (IPv4), `internal`, `try_files`, `index`, `root`/`alias`,
`error_page`, `proxy_pass` URI rewriting, `proxy_set_header`, `upstream`.

Assumptions, always stated in the step where they apply:

- Disk contents are unknown: list existing files in the page to resolve
  `try_files`, `if (-f …)`, `index` and static serving.
- Authentication, rate limits and `auth_request` are shown and assumed to pass.
- For an `upstream` group the first non-backup server is followed.
- Regexes are run by the browser's engine; PCRE-only syntax that cannot be
  translated is flagged and treated as not matching.
- Variables the tool does not know are treated as empty and listed.
- Lua blocks, njs, `geo`, `split_clients` and third-party modules are not
  evaluated.

It is an analysis aid, not a replacement for `nginx -t` or a test request.

## Licence

MIT. See [LICENSE](LICENSE).
