#!/usr/bin/env python3
"""Regenerates the README pictures from the example page.

    python3 docs/make-demo.py

Reads examples/out/nginx-flow.html (regenerate it first, see the README) and
writes docs/demo.gif, docs/trace.png and docs/verify.png.

It drives the real page: a copy gets a few lines of script appended that read
the URL fragment, type a URL into the box, press Trace and move to a step, and
headless Chrome takes a picture of each state. The copy has the page's
Content-Security-Policy removed, because the appended lines change the script
the policy pins. Needs Google Chrome (or Chromium) and ffmpeg.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "..", "examples", "out", "nginx-flow.html")
URL = "https://example.com/old-blog/hello-world"
SIZE = (1280, 800)
CHROMES = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
           "/Applications/Chromium.app/Contents/MacOS/Chromium",
           "google-chrome", "chromium", "chromium-browser"]

DRIVER = r"""
/* appended by docs/make-demo.py */
(function(){
  let f; try { f = JSON.parse(decodeURIComponent(location.hash.slice(1))); } catch (e) { return; }
  if (f.typed != null) $('url').value = f.typed;
  if (f.focus) $('url').focus();
  if (f.trace) { run(); stopPlay(); show(f.step || 0); }
  if (f.open) document.querySelector(f.open).open = true;
  if (f.scroll) document.querySelector(f.scroll).scrollIntoView({block: 'start'});
  document.title = 'steps=' + STEPS.length;
})();
"""


def chrome():
    for c in CHROMES:
        p = c if os.path.exists(c) else shutil.which(c)
        if p:
            return p
    sys.exit("Google Chrome or Chromium not found")


def main():
    html = open(PAGE, encoding="utf-8").read()
    html, n = re.subn(r'<meta http-equiv="Content-Security-Policy"[^>]*>\n', "", html)
    assert n == 1, "Content-Security-Policy meta tag not found"
    i = html.rindex("</script>")
    html = html[:i] + DRIVER + html[i:]
    tmp = tempfile.mkdtemp(prefix="nginxviz-demo-")
    page = os.path.join(tmp, "page.html")
    open(page, "w", encoding="utf-8").write(html)
    exe = chrome()

    def run_chrome(state, *args):
        url = "file://" + page + "#" + urllib.parse.quote(json.dumps(state))
        return subprocess.run([exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                               "--user-data-dir=" + os.path.join(tmp, "profile"), *args, url],
                              capture_output=True, text=True, timeout=120)

    def shot(state, out, scale=1, size=SIZE):
        run_chrome(state, "--screenshot=" + out, "--window-size=%d,%d" % size,
                   "--force-device-scale-factor=%d" % scale)
        assert os.path.exists(out), "no screenshot for %r" % (state,)

    # how many steps does the trace have?
    dom = run_chrome({"typed": URL, "trace": True}, "--dump-dom").stdout
    steps = int(re.search(r"<title>steps=(\d+)</title>", dom).group(1))
    print("trace has", steps, "steps")

    # frames: (state, how many 1/10 s to hold it)
    frames = [({}, 12)]
    for k in range(8, len(URL) + 1, 4):
        frames.append(({"typed": URL[:k], "focus": True}, 1))
    frames.append(({"typed": URL, "focus": True}, 6))
    for s in range(steps):
        frames.append(({"typed": URL, "trace": True, "step": s}, 30 if s == steps - 1 else 11))

    listing = []
    for n, (state, hold) in enumerate(frames):
        png = os.path.join(tmp, "f%03d.png" % n)
        shot(state, png)
        listing += ["file '%s'" % png, "duration %.1f" % (hold / 10)]
    listing.append(listing[-2])  # the concat demuxer needs the last file twice
    concat = os.path.join(tmp, "frames.txt")
    open(concat, "w").write("\n".join(listing) + "\n")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", concat,
                    "-vf", "scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];"
                           "[b][p]paletteuse=dither=none:diff_mode=rectangle",
                    "-fps_mode", "vfr", os.path.join(HERE, "demo.gif")], check=True)

    shot({"typed": URL, "trace": True, "step": min(steps - 1, 9)}, os.path.join(HERE, "trace.png"), scale=2, size=(1440, 900))
    shot({"open": "#verify", "scroll": "#verify"}, os.path.join(HERE, "verify.png"), scale=2, size=(1440, 900))
    shutil.rmtree(tmp)
    for f in ("demo.gif", "trace.png", "verify.png"):
        print(f, os.path.getsize(os.path.join(HERE, f)) // 1024, "KB")


if __name__ == "__main__":
    main()
