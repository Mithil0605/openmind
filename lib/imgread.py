#!/usr/bin/env python3
"""
imgread.py - make images readable by an LLM agent. Shipped with OpenMind v5.

Reads ONLY image documents (PNG/JPEG/GIF/BMP/WEBP/TIFF by magic bytes, SVG as
text, PDF by rasterizing its pages). This helper deliberately refuses non-image
files so it cannot be used to exfiltrate arbitrary file contents.

Features (and the limitations each one removes):
  1. Web URLs         -> downloads public URLs to a temp file, size-capped
  2. Large images     -> downscales, and can emit the normalized PNG for the
                         agent to attach back to the model as a real image
  3. Fine text/OCR    -> runs tesseract and prints the extracted text
  4. Vector images    -> dumps SVG markup as text
  5. PDFs             -> rasterizes pages with poppler/mupdf/ghostscript, then
                         analyzes (and OCRs) the resulting raster pages
  6. Rare/corrupt     -> reports type/refusal without leaking content

Security:
  - SSRF guard: URL hosts are DNS-resolved and any private/loopback/link-local
    (including cloud-metadata 169.254.169.254) address blocks the fetch.
    Redirects are re-checked per hop, max 5.
  - Download is streamed against a hard byte cap and a wall-clock deadline, so a
    hostile or endless response can never fill the temp dir or hang the agent.
  - Every external binary is invoked with an argument array (never a shell), and
    paths are resolved before they are handed over.
  - Output caps: OCR <= 8000 chars, SVG <= 8000 chars, analysis <= 24000 chars.
    The image bytes themselves are never hexdumped.
  - Home-directory prefixes in printed paths are redacted to "~".

Usage:
  python3 imgread.py <path-or-url> [--no-ocr] [--max 1400] [--pages 1]
                     [--emit-png <path>]
"""

import argparse
import http.client
import ipaddress
import os
import re
import shutil
import socket
# Bandit B404: every use of subprocess here is an argv-list call (never a shell)
# with a tool located by which() on a fixed literal, so there is no injection
# surface. See rasterize_pdf and run_ocr for the argument construction.
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:  # pragma: no cover
    HAS_PIL = False

OCR_MAX_DIM = 1400
OCR_TEXT_CAP = 8000
SVG_CAP = 8000
OUTPUT_CAP = 24000
DOWNLOAD_TIMEOUT = 15          # per socket operation
DOWNLOAD_DEADLINE = 30         # wall clock for the whole download
DOWNLOAD_MAX_BYTES = 25 * 1024 * 1024
MAX_REDIRECTS = 5
ALLOWED_PORTS = frozenset((80, 443, 8000, 8080, 8443))
PDF_PAGE_LIMIT = 5
SUBPROCESS_TIMEOUT = 30

# PDF rasterizers, in preference order. Each entry is (binary, argv-builder).
PDF_RASTERIZERS = ("pdftoppm", "pdftocairo", "mutool", "gs")


def printable_only(text):
    # Keep tab/newline/carriage-return so OCR output stays readable; every other
    # control character (including ESC, so ANSI escapes cannot reach the model)
    # becomes a dot.
    return "".join(
        ch if ch in "\t\n\r" or 32 <= ord(ch) < 127 else "." for ch in text
    )


def redact(path):
    home = os.path.expanduser("~")
    if home and path.startswith(home):
        return "~" + path[len(home):]
    return path


def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or addr.is_loopback or addr.is_link_local:
            return True
        if isinstance(addr, ipaddress.IPv4Address):
            if addr.is_private:  # 10/8, 172.16/12, 192.168/16
                return True
            if 0x64400000 <= int(addr) <= 0x647FFFFF:
                return True  # 100.64.0.0/10 CGNAT
        return False
    except ValueError:
        return True


def resolve_public(host, port):
    """Return the vetted public IP for `host`, or None.

    The IP is returned rather than a yes/no so the caller can pin the connection
    to it. Returning only a boolean leaves a DNS-rebinding hole: urllib resolves
    the hostname a second time when it opens the socket, so an attacker with a
    short-TTL record can answer 127.0.0.1 on that second lookup.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return None
    ips = []
    for info in infos:
        ip = info[4][0]
        if is_private_ip(ip):
            return None  # one private answer blocks the whole name
        ips.append(ip)
    return ips[0] if ips else None


def check_url_shape(url):
    """Validate scheme/host/port and return (host, port), or raise ValueError."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("refused: only http and https URLs are supported")
    host = parsed.hostname
    if not host:
        raise ValueError("refused: the URL has no host")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("refused: the URL has an invalid port")
    if port is not None and port not in ALLOWED_PORTS:
        # Same allowlist the plugin applies, so the helper cannot be used to
        # reach an internal service on an unusual port.
        raise ValueError(
            "refused: port %s is not allowed (permitted: %s)"
            % (port, ", ".join(str(p) for p in sorted(ALLOWED_PORTS)))
        )
    return host, port or (443 if parsed.scheme == "https" else 80)


# Vetted addresses, keyed by hostname. Populated before every request (and again
# for every redirect hop) by resolve_public; the connection classes below refuse
# to dial a host that is not in here, so the address that was screened is the
# address that is used. Host name and port stay intact for the Host header, TLS
# SNI and certificate verification.
_PINNED = {}


class _PinnedMixin:
    def connect(self):
        """Dial the vetted IP instead of re-resolving the hostname.

        Mirrors http.client's own connect(): create the socket, connect, tunnel
        if a proxy tunnel is configured, then wrap for TLS when this connection
        has an SSL context. Only HTTPSConnection defines _context (it defaults to
        a verifying context); a plain HTTPConnection has no such attribute, so it
        is read with getattr rather than touched directly.
        """
        ip = _PINNED.get(self.host)
        if not ip:
            raise urllib.error.URLError("refused: no vetted address for %s" % self.host)
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((ip, self.port))
        except OSError:
            self.sock.close()
            raise
        tunnel_host = getattr(self, "_tunnel_host", None)
        if tunnel_host:
            self._tunnel()
        context = getattr(self, "_context", None)
        if context is not None:
            # server_hostname drives both SNI and certificate hostname
            # verification, so the certificate is still checked against the name
            # that was screened, not against the vetted IP.
            self.sock = context.wrap_socket(
                self.sock, server_hostname=tunnel_host or self.host)


class PinnedHTTPConnection(_PinnedMixin, http.client.HTTPConnection):
    pass


class PinnedHTTPSConnection(_PinnedMixin, http.client.HTTPSConnection):
    pass


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(PinnedHTTPConnection, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(PinnedHTTPSConnection, req,
                            context=self._context)


class BlockedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        try:
            host, port = check_url_shape(newurl)
        except ValueError:
            raise urllib.error.URLError("blocked redirect to a non-public address")
        ip = resolve_public(host, port)
        if not ip:
            raise urllib.error.URLError("blocked redirect to a non-public address")
        _PINNED[host] = ip  # re-screen and re-pin the hop we are about to take
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_public(url):
    """Stream a public URL to a temp file under a byte cap and a deadline."""
    host, port = check_url_shape(url)
    ip = resolve_public(host, port)
    if not ip:
        raise ValueError("refused: URL host is not public (private/loopback/link-local addresses are blocked for security)")
    _PINNED[host] = ip
    opener = urllib.request.build_opener(
        # An empty ProxyHandler disables proxy support outright. Without it,
        # build_opener installs a proxy whenever http_proxy/https_proxy is set,
        # and a proxied request would dial the *proxy* instead of the pinned
        # address. That is fail-closed (the pin refuses an unknown host) but it
        # silently breaks URL support on any machine with a proxy configured.
        urllib.request.ProxyHandler({}),
        BlockedRedirect,
        PinnedHTTPHandler,
        PinnedHTTPSHandler,
    )
    opener.addheaders = [("User-Agent", "openmind-imgread/5.0")]
    tmp = tempfile.NamedTemporaryFile(prefix="omimg-", suffix=".bin", delete=False)
    tmp.close()
    started = time.monotonic()
    try:
        with opener.open(url, timeout=DOWNLOAD_TIMEOUT) as resp, open(tmp.name, "wb") as out:
            total = 0
            while True:
                if time.monotonic() - started > DOWNLOAD_DEADLINE:
                    raise ValueError("refused: download exceeded the %ds time budget" % DOWNLOAD_DEADLINE)
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > DOWNLOAD_MAX_BYTES:
                    raise ValueError("refused: download exceeded the %dMB cap" % (DOWNLOAD_MAX_BYTES // 1024 // 1024))
                out.write(chunk)
        return tmp.name, resp.headers.get("Content-Type", "").split(";")[0].strip()
    except Exception:
        os.unlink(tmp.name)
        raise


def sniff_type(path):
    with open(path, "rb") as f:
        head = f.read(64)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG (raster)"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG (raster)"
    if head.startswith(b"GIF8"):
        return "GIF (animated raster)"
    if head.startswith(b"BM"):
        return "BMP (raster)"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "WEBP (raster)"
    if head.startswith(b"II*\x00") or head.startswith(b"MM\x00*"):
        return "TIFF (raster)"
    if head.startswith(b"%PDF"):
        return "PDF"
    stripped = head.lstrip()
    if stripped.startswith(b"<svg"):
        return "SVG"
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<"):
        return "XML"
    return None


def dump_svg(path):
    with open(path, "r", errors="replace") as f:
        return f.read(SVG_CAP)


def which(binary):
    return shutil.which(binary)


def pdf_page_count(path):
    """Best-effort page count from the PDF page tree; 0 when unknown."""
    try:
        with open(path, "rb") as f:
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return 0
    counts = [int(m) for m in re.findall(rb"/Type\s*/Pages\b[^>]*?/Count\s+(\d+)", data)]
    if counts:
        return max(counts)
    return len(re.findall(rb"/Type\s*/Page\b", data))


def rasterize_pdf(path, out_dir, pages):
    """Rasterize the first `pages` PDF pages to PNG. Returns a list of paths.

    Bandit flags every subprocess call below as B603. They are safe by
    construction: the program name comes from which() on a fixed literal, the
    arguments are integers or paths this function itself created inside a
    mkdtemp directory, no shell is involved, and every call is time-boxed. There
    is no untrusted string interpolated into a command line.
    """
    pdftoppm = which("pdftoppm")
    if pdftoppm:
        prefix = os.path.join(out_dir, "page")
        subprocess.run(  # nosec B603
            [pdftoppm, "-png", "-r", "150", "-f", "1", "-l", str(pages), path, prefix],
            capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT * pages,
        )
        return sorted(_glob(out_dir, "page-*.png"))

    pdftocairo = which("pdftocairo")
    if pdftocairo:
        prefix = os.path.join(out_dir, "page")
        subprocess.run(  # nosec B603
            [pdftocairo, "-png", "-r", "150", "-f", "1", "-l", str(pages), path, prefix],
            capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT * pages,
        )
        return sorted(p for p in _glob(out_dir, "page-*.png"))

    mutool = which("mutool")
    if mutool:
        out = []
        for index in range(1, pages + 1):
            target = os.path.join(out_dir, "page-%02d.png" % index)
            subprocess.run(  # nosec B603
                [mutool, "draw", "-o", target, "-r", "150", path, str(index)],
                capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
            )
            if os.path.exists(target):
                out.append(target)
        return out

    gs = which("gs")
    if gs:
        out = []
        for index in range(1, pages + 1):
            target = os.path.join(out_dir, "page-%02d.png" % index)
            subprocess.run(  # nosec B603
                [gs, "-q", "-dNOPAUSE", "-dBATCH", "-dSAFER", "-sDEVICE=png16m",
                 "-r150", "-dFirstPage=%d" % index, "-dLastPage=%d" % index,
                 "-sOutputFile=" + target, path],
                capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
            )
            if os.path.exists(target):
                out.append(target)
        return out

    return []


def _glob(directory, pattern):
    import glob as _g
    return _g.glob(os.path.join(directory, pattern))


def raster_info(path):
    img = Image.open(path)
    img.load()
    w, h = img.size
    return img, w, h


def run_ocr(img_path):
    """Return OCR text, or None when tesseract is unavailable or found nothing.

    argv-list call with a binary located by which() and a path this process
    created with mkstemp, no shell, time-boxed. Not an injection surface.
    """
    tesseract_bin = which("tesseract")
    if not tesseract_bin:
        return None
    try:
        proc = subprocess.run(  # nosec B603
            [tesseract_bin, img_path, "stdout"],
            capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = printable_only((proc.stdout or "").strip())[:OCR_TEXT_CAP]
    return text or None


def analyze_raster(path, out, no_ocr, max_dim, emit_png, ocr_results, ocr_paths):
    kind = sniff_type(path)
    if not HAS_PIL:
        out.append("[type] %s" % kind)
        out.append("[note] PIL is not installed; install Pillow and tesseract for full image reading.")
        return
    try:
        img, w, h = raster_info(path)
    except Exception as e:  # PIL syntax/truncation errors
        out.append("[type] %s" % kind)
        out.append("[error] image is corrupt or unreadable: %s" % type(e).__name__)
        return

    out.append("[type] %s" % kind)
    out.append("[raster] %dx%d, mode=%s, format=%s, frames=%d"
               % (w, h, img.mode, getattr(img, "format", "?"), getattr(img, "n_frames", 1)))

    scale = max_dim / max(w, h) if max(w, h) else 1
    if scale < 1:
        nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
        img = img.convert("RGB").resize((nw, nh), Image.LANCZOS)
        out.append("[resize] %dx%d -> %dx%d" % (w, h, nw, nh))

    if emit_png:
        img.convert("RGB").save(emit_png, "PNG")
        out.append("[png] normalized PNG prepared for attachment")

    if not no_ocr:
        # mkstemp, not a name built from the pid: a predictable path in a
        # world-writable directory lets a local attacker pre-place a symlink and
        # have the PNG written through it, clobbering any file this user can write.
        handle, ocr_path = tempfile.mkstemp(prefix="omimg_ocr_", suffix=".png")
        os.close(handle)
        ocr_paths.append(ocr_path)
        try:
            img.convert("RGB").save(ocr_path, "PNG")
            ocr_results.append(run_ocr(ocr_path))
        finally:
            try:
                os.unlink(ocr_path)
            except OSError:
                pass


def analyze(path, opts, out, ocr_results, ocr_paths):
    if not os.path.exists(path):
        return "error: no such file: %s" % redact(path)
    kind = sniff_type(path)
    if kind is None:
        return ("Not a recognized image format (PNG/JPEG/GIF/BMP/WEBP/TIFF/SVG/PDF). "
                "OpenMind image_read reads only image files; no other file contents are shown.")

    if kind == "SVG":
        out.append("[type] SVG (vector - markup below)")
        out.append("[svg] %d chars:" % min(os.path.getsize(path), SVG_CAP))
        out.append(printable_only(dump_svg(path)))
        return None

    if kind == "PDF":
        return analyze_pdf(path, opts, out, ocr_results, ocr_paths)

    analyze_raster(path, out, opts.no_ocr, opts.max, opts.emit_png, ocr_results, ocr_paths)
    return None


def analyze_pdf(path, opts, out, ocr_results, ocr_paths):
    total = pdf_page_count(path)
    want = max(1, min(opts.pages, PDF_PAGE_LIMIT))
    out.append("[type] PDF (document)")
    out.append("[pdf] %s, %s page(s) detected" % (redact(path), total or "unknown"))
    if not any(which(name) for name in PDF_RASTERIZERS):
        out.append("[error] PDF rasterization needs one of: %s" % ", ".join(PDF_RASTERIZERS))
        out.append("[hint] Install poppler-utils (pdftoppm) or mupdf-tools, then retry; "
                   "no PDF text or image content is shown.")
        return None

    work = tempfile.mkdtemp(prefix="ompdf-")
    try:
        pages = rasterize_pdf(path, work, want)
        if not pages:
            out.append("[error] the PDF rasterizer produced no page images; "
                       "the document may be encrypted or malformed.")
            return None
        for index, page in enumerate(pages, 1):
            out.append("")
            out.append("--- PDF page %d/%d ---" % (index, len(pages)))
            # Only the first page is attached to the model: one attachment per
            # call keeps the context cost bounded and predictable.
            emit = opts.emit_png if (index == 1 and opts.emit_png) else None
            analyze_raster(page, out, opts.no_ocr, opts.max, emit, ocr_results, ocr_paths)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return None


def format_report(out, ocr_results, no_ocr):
    lines = list(out)
    if not no_ocr and not any(line.startswith("[ocr]") for line in lines):
        found = " | ".join(result for result in ocr_results if result)
        if found:
            lines.append("\n[ocr] %s" % found[:OCR_TEXT_CAP])
        elif which("tesseract") is None:
            lines.append("\n[ocr] tesseract not installed; OCR skipped")
        else:
            lines.append("\n[ocr] no readable text detected")
    return printable_only("\n".join(lines))[:OUTPUT_CAP]


def main(argv):
    parser = argparse.ArgumentParser(prog="imgread", add_help=True)
    parser.add_argument("target", help="local image/PDF path or http(s) URL")
    parser.add_argument("--no-ocr", action="store_true", help="skip OCR and report format/dimensions only")
    parser.add_argument("--max", type=int, default=OCR_MAX_DIM, help="cap for the longest side before downscaling")
    parser.add_argument("--pages", type=int, default=1, help="PDF pages to rasterize (max %d)" % PDF_PAGE_LIMIT)
    parser.add_argument("--emit-png", default=None, help="write the normalized/downscaled PNG here for model attachment")
    args = parser.parse_args(argv)

    args.max = max(128, min(args.max, 4096))
    args.pages = max(1, min(args.pages, PDF_PAGE_LIMIT))
    if args.emit_png:
        args.emit_png = os.path.abspath(os.path.expanduser(args.emit_png))

    target = args.target
    if target.startswith("-"):
        print("error: target must be a file path or http(s) URL, not a flag.")
        return 2

    tmp = None
    work = None
    out = []
    ocr_results = []
    ocr_paths = []
    try:
        if target.startswith("http://") or target.startswith("https://"):
            tmp, ctype = download_public(target)
            src = tmp
            print("[downloaded] %s (%s bytes, %s)" % (redact(target), os.path.getsize(src), ctype or "no type"))
        else:
            src = target
            print("[file] %s (%s bytes)" % (redact(target), os.path.getsize(target)))
        error = analyze(src, args, out, ocr_results, ocr_paths)
        if error:
            print(printable_only(error)[:OUTPUT_CAP])
            return 1 if error.startswith("error:") else 0
        print(format_report(out, ocr_results, args.no_ocr))
        return 0
    except urllib.error.HTTPError as e:
        print("error: download failed with HTTP %d" % e.code)
        return 1
    except urllib.error.URLError as e:
        print("error: download failed: %s" % (e.reason or e))
        return 1
    except ValueError as e:
        print("error: %s" % e)
        return 1
    except OSError as e:
        print("error: %s" % (e.strerror or e))
        return 1
    except Exception:
        print("error: unexpected failure while reading the image")
        return 1
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        for leftover in ocr_paths:
            try:
                os.unlink(leftover)
            except OSError:
                pass
        if work:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))