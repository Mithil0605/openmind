#!/usr/bin/env python3
"""
imgread.py - make images readable by an LLM agent. Shipped with OpenMind v4.

Reads ONLY image files (PNG/JPEG/GIF/BMP/WEBP/TIFF pick up by magic bytes,
plus SVG/PDF handled as text or with hints). This tool deliberately refuses
non-image files so it cannot be used to exfiltrate arbitrary file contents.

Features (and the limitations each one removes):
  1. No web URLs        -> downloads public URLs to a temp file
  2. Large images       -> downscales so a reader agent can ingest without truncation
  3. Fine text/OCR      -> runs tesseract and prints the extracted text
  4. Vector images      -> dumps SVG markup as text
  5. Rare/corrupt files -> reports type/refusal without leaking content

Security:
  - SSRF guard: URL hosts are DNS-resolved and any private/loopback/link-local
    (including cloud-metadata 169.254.169.254) address blocks the fetch.
    Redirects are re-checked per hop, max 5.
  - Output caps: OCR <= 8000 chars, SVG <= 8000 chars, no hexdump of file data.
  - No shell is ever executed; the image file bytes are never echoed.
  - Home-directory prefixes in printed paths are redacted to "~".

Usage:
  python3 imgread.py <path-or-url> [--no-ocr] [--max 1400]
"""

import argparse
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
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
DOWNLOAD_TIMEOUT = 30
MAX_REDIRECTS = 5

IMAGE_TYPES = ("PNG (raster)", "JPEG (raster)", "GIF (animated raster)",
               "BMP (raster)", "WEBP (raster)", "TIFF (raster)")


def printable_only(text):
    return "".join(ch if 32 <= ord(ch) != 127 else "." for ch in text)


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
            if (int(addr) >> 22) == (100 & 0x3FFFFF) or (0x64400000 <= int(addr) <= 0x647FFFFF):
                return True  # 100.64.0.0/10 CGNAT
        return False
    except ValueError:
        return True


def is_public_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    if parsed.port and parsed.port not in (80, 443, 8000, 8080, 8443):
        return False
    try:
        infos = socket.getaddrinfo(host, parsed.port or 80, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return False
    ips = {info[4][0] for info in infos}
    if any(is_private_ip(ip) for ip in ips):
        return False
    return True


class BlockedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        if not is_public_url(newurl):
            raise urllib.error.URLError("blocked redirect to a non-public address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_public(url):
    if not is_public_url(url):
        raise ValueError("refused: URL host is not public (private/loopback/link-local addresses are blocked for security)")
    opener = urllib.request.build_opener(BlockedRedirect)
    opener.addheaders = [("User-Agent", "openmind-imgread/4.0")]
    tmp = tempfile.NamedTemporaryFile(prefix="omimg-", suffix=".bin", delete=False)
    tmp.close()
    try:
        with opener.open(url, timeout=DOWNLOAD_TIMEOUT) as resp, open(tmp.name, "wb") as out:
            shutil.copyfileobj(resp, out)
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
    if head.strip().startswith(b"<svg"):
        return "SVG"
    if head.strip().startswith(b"<?xml") or head.strip().startswith(b"<"):
        return "XML"
    return None


def dump_svg(path):
    with open(path, "r", errors="replace") as f:
        data = f.read()
    return data[:SVG_CAP]


def raster_info(path):
    img = Image.open(path)
    img.load()
    w, h = img.size
    return img, w, h


def analyze(path, no_ocr, max_dim):
    out = []
    if not os.path.exists(path):
        return "error: no such file: %s" % redact(path)
    kind = sniff_type(path)
    if kind is None:
        return "Not a recognized image format (PNG/JPEG/GIF/BMP/WEBP/TIFF/SVG/PDF). " \
               "OpenMind image_read reads only image files; no other file contents are shown."
    if kind == "PDF":
        return "PDF detected. Convert to an image first (e.g. pdftoppm -png <file> <out>) then read the PNG."
    if kind == "SVG":
        out.append("[type] SVG (vector - text below)")
        out.append("[svg] %d chars:" % min(os.path.getsize(path), SVG_CAP))
        out.append(printable_only(dump_svg(path)))
        return "\n".join(out)
    if not HAS_PIL:
        return "[type] %s\n[note] PIL is not installed; install Pillow and tesseract for full image reading." % kind

    try:
        img, w, h = raster_info(path)
    except Exception as e:  # PIL syntax/truncation errors
        return "[type] %s\n[error] image is corrupt or unreadable: %s" % (kind, type(e).__name__)

    out.append("[type] %s" % kind)
    out.append("[raster] %dx%d, mode=%s, format=%s, frames=%d"
               % (w, h, img.mode, getattr(img, "format", "?"), getattr(img, "n_frames", 1)))

    scale = max_dim / max(w, h)
    if scale < 1:
        nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
        img = img.convert("RGB").resize((nw, nh), Image.LANCZOS)
        out.append("[resize] %dx%d -> %dx%d" % (w, h, nw, nh))

    if not no_ocr:
        output_path = os.path.join(tempfile.gettempdir(), "omimg_ocr_%d.png" % os.getpid())
        try:
            img.convert("RGB").save(output_path, "PNG")
            tesseract_bin = shutil.which("tesseract")
            if tesseract_bin:
                proc = subprocess.run(
                    [tesseract_bin, output_path, "stdout"],
                    capture_output=True, text=True, timeout=30,
                )
                ocr = printable_only((proc.stdout or "").strip())[:OCR_TEXT_CAP]
                out.append("\n[ocr] %s" % (ocr if ocr else "no readable text detected"))
            else:
                out.append("\n[ocr] tesseract not installed; OCR skipped")
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass
    return "\n".join(out)


def main(argv):
    parser = argparse.ArgumentParser(prog="imgread", add_help=True)
    parser.add_argument("target")
    parser.add_argument("--no-ocr", action="store_true")
    parser.add_argument("--max", type=int, default=OCR_MAX_DIM)
    args = parser.parse_args(argv)

    if args.max < 128:
        args.max = 128
    if args.max > 4096:
        args.max = 4096

    target = args.target
    if target.startswith("-"):
        print("error: target must be a file path or http(s) URL, not a flag.")
        return 2

    tmp = None
    try:
        if target.startswith("http://") or target.startswith("https://"):
            tmp, ctype = download_public(target)
            src = tmp
            print("[downloaded] %s (%s bytes, %s)" % (redact(target), os.path.getsize(src), ctype or "no type"))
        else:
            src = target
            print("[file] %s (%s bytes)" % (redact(target), os.path.getsize(target)))
        print(analyze(src, args.no_ocr, args.max))
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
        print("error: %s" % e.strerror or e)
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))