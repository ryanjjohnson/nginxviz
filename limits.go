package main

import (
	"strings"
	"unicode/utf8"
)

// Hard limits on what the input may cost. Config files and URL lists can come
// from anywhere (a ticket, a repository, another team); nothing in them can
// make nginxviz use more than these allow.
const (
	// maxFileBytes caps one config file. Real nginx configs are kilobytes.
	maxFileBytes = 8 << 20

	// maxConfigBytes caps one config together with everything it includes.
	// It also bounds the size of the outputs, which embed the config.
	maxConfigBytes = 32 << 20

	// maxFiles caps how many files one config may pull in through include.
	// Together with maxIncludeDepth it stops include loops and fan-out bombs.
	maxFiles = 2000

	// maxIncludeDepth caps include nesting.
	maxIncludeDepth = 20

	// maxBlockDepth caps { } nesting, and with it parser and renderer
	// recursion. Real configs nest four or five deep.
	maxBlockDepth = 64

	// maxDirectives caps the parsed tree of one config.
	maxDirectives = 200_000

	// maxArgs caps the arguments of one directive.
	maxArgs = 4096

	// maxCasesBytes, maxCaseLine and maxCases cap the -verify URL file.
	maxCasesBytes = 4 << 20
	maxCaseLine   = 16 << 10
	maxCases      = 5000

	// maxResponseBytes caps how much of one scratch-nginx response is read.
	maxResponseBytes = 16 << 20

	// maxLogBytes caps how much new nginx debug log is read per request.
	maxLogBytes = 32 << 20

	// maxListenPorts and maxStubs cap the listeners one -verify run opens:
	// one per distinct listen port of a config, one per distinct backend.
	maxListenPorts = 64
	maxStubs       = 256

	// maxCertNames caps the host names put on the scratch TLS certificate.
	maxCertNames = 200

	// maxMessage caps one warning or error line.
	maxMessage = 2000
)

// clean makes text taken from a config or URL file safe to print on a
// terminal or put on one line of a report: control characters (including
// escape, newline and the Unicode bidi overrides) become "?", invalid UTF-8
// is replaced, and the result is cut at maxMessage bytes.
func clean(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if sb.Len() >= maxMessage {
			sb.WriteString("…")
			break
		}
		switch {
		case r == utf8.RuneError:
			sb.WriteRune('�')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			sb.WriteByte('?')
		case r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0xfeff:
			sb.WriteByte('?')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// cleanMultiline is clean for text that legitimately spans lines (nginx's own
// output): newlines and tabs survive, everything else is treated as in clean.
func cleanMultiline(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if len(lines) > 60 {
		lines = append(lines[:60], "…")
	}
	for i, l := range lines {
		lines[i] = clean(strings.ReplaceAll(l, "\t", "    "))
	}
	return strings.Join(lines, "\n")
}
