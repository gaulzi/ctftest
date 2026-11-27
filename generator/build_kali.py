#!/usr/bin/env python3
"""Generate the "Kali Toolbox" (Season 2) practice CTF.

    python3 generator/build_kali.py

Harder than Season 1, and organised around the Kali tools you'd actually reach
for in a mixed CTF. Writes evidence into kali-tools/challenges/<id>/ and flag
hashes into kali-tools/portal/flags.js.

SPOILER WARNING: every flag is in this file in clear text.
"""
import base64, gzip, hashlib, io, os, struct, subprocess, sys, wave, zlib, codecs, random, shutil, json, hmac
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import qrcode
from passlib.hash import sha512_crypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(__file__))
from pcaplib import Pcap, TcpSession  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "kali-tools", "challenges")
FLAGS = {}
random.seed(31337)
np.random.seed(31337)


def cdir(cid):
    d = os.path.join(OUT, cid)
    os.makedirs(d, exist_ok=True)
    return d


def wtext(cid, name, text):
    with open(os.path.join(cdir(cid), name), "w", newline="\n") as f:
        f.write(text)


def wbin(cid, name, data):
    with open(os.path.join(cdir(cid), name), "wb") as f:
        f.write(data)


def flag(cid, v):
    FLAGS[cid] = v


def font(sz):
    for p in ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]:
        if os.path.exists(p):
            return ImageFont.truetype(p, sz)
    return ImageFont.load_default()


# ---------------------------------------------------------------- s01 tshark
def c_tshark():
    cid = "s01-tshark-exfil"
    fl = "AVIANS{follow_the_tcp_stream}"
    flag(cid, fl)
    # a password-protected zip transferred over HTTP; recover it, then crack it.
    pw = "cockpit1"   # in the aviation wordlist
    tmp = os.path.join(cdir(cid), "_t")
    os.makedirs(tmp, exist_ok=True)
    with open(os.path.join(tmp, "secret_route.txt"), "w") as f:
        f.write("Classified crew note.\n" + fl + "\n")
    zf = os.path.join(tmp, "payload.zip")
    if os.path.exists(zf):
        os.remove(zf)
    subprocess.run(["zip", "-q", "-j", "-P", pw, zf, os.path.join(tmp, "secret_route.txt")], check=True)
    zbytes = open(zf, "rb").read()
    shutil.rmtree(tmp)
    p = Pcap(1731560400.0)
    # noise
    s0 = TcpSession(p, "10.7.7.21", 44001, "10.7.0.9", 80).handshake()
    s0.client(b"GET /status HTTP/1.1\r\nHost: ops.avians.local\r\n\r\n")
    s0.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    s0.close()
    # the exfil download
    s = TcpSession(p, "10.7.7.21", 44002, "10.7.0.9", 80).handshake()
    s.client(b"GET /files/payload.zip HTTP/1.1\r\nHost: ops.avians.local\r\nUser-Agent: curl/8.5.0\r\n\r\n")
    s.server(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/zip\r\n"
             b"Content-Disposition: attachment; filename=\"payload.zip\"\r\nContent-Length: %d\r\n\r\n" % len(zbytes) + zbytes)
    s.close()
    p.save(os.path.join(cdir(cid), "capture.pcap"))
    wtext(cid, "note.txt", "A file was pulled off the ops server over plain HTTP.\n"
          "Carve the transferred file out of the capture, then open it.\n")


# ---------------------------------------------------------------- s02 binwalk
def c_binwalk():
    cid = "s02-binwalk-carve"
    fl = "AVIANS{carved_from_the_blob}"
    flag(cid, fl)
    png = _text_png("DECOY", 200, 80, (20, 30, 50))
    gz = gzip.compress(b"nothing to see here\n", mtime=0)
    inner = io.BytesIO()
    import zipfile
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("flag.txt", fl + "\n")
    blob = b"FIRMWARE-IMG\x00" + bytes(random.randrange(256) for _ in range(1500))
    blob += png + bytes(random.randrange(256) for _ in range(800))
    blob += gz + bytes(random.randrange(256) for _ in range(600))
    blob += inner.getvalue() + bytes(random.randrange(256) for _ in range(400))
    wbin(cid, "recovered.img", blob)
    wtext(cid, "note.txt", "A raw image pulled from a dashboard flash chip. Several files are hiding in it.\n")


# ---------------------------------------------------------------- s03 zsteg
def _cover(w, h):
    g = np.zeros((h, w, 3), np.uint8)
    for y in range(h):
        g[y, :, 0] = 40 + int(60 * y / h)
        g[y, :, 1] = 60 + int(40 * y / h)
        g[y, :, 2] = 90 + int(50 * y / h)
    g = (g.astype(int) + np.random.randint(-6, 7, g.shape)).clip(0, 255).astype(np.uint8)
    return g


def c_zsteg():
    cid = "s03-zsteg-lsb"
    fl = "AVIANS{least_significant_bird}"
    flag(cid, fl)
    w, h = 220, 140
    img = _cover(w, h)
    bits = []
    for ch in (fl + "\x00").encode():
        for i in range(7, -1, -1):
            bits.append((ch >> i) & 1)
    # zsteg b1,rgb,lsb,xy : LSB of R,G,B across pixels in row-major order
    flatidx = 0
    for i, bit in enumerate(bits):
        px = i // 3
        ch = i % 3
        y, x = divmod(px, w)
        img[y, x, ch] = (int(img[y, x, ch]) & 0xFE) | bit
    Image.fromarray(img, "RGB").save(os.path.join(cdir(cid), "approach_chart.png"))
    wtext(cid, "note.txt", "Looks like an ordinary chart thumbnail. The LSBs say otherwise.\n")


# ---------------------------------------------------------------- s04 sox / spectrogram
def c_spectrogram():
    cid = "s04-spectrogram"
    fl = "AVIANS{i_can_see_your_voice}"
    flag(cid, fl)
    text = "AVIANS{i_can_see_your_voice}"
    iw, ih = 560, 70
    im = Image.new("L", (iw, ih), 0)
    d = ImageDraw.Draw(im)
    d.text((6, 6), text, fill=255, font=font(44))
    arr = np.array(im)
    arr = np.flipud(arr)  # so high freq = top of text
    sr = 22050
    col_t = 0.02
    spc = int(sr * col_t)
    fmin, fmax = 600, 7000
    out = np.zeros(iw * spc, np.float32)
    rows = ih
    freqs = np.linspace(fmin, fmax, rows)
    tt = np.arange(spc) / sr
    for x in range(iw):
        col = arr[:, x]
        on = np.where(col > 128)[0]
        if len(on) == 0:
            continue
        seg = np.zeros(spc, np.float32)
        for r in on:
            seg += np.sin(2 * np.pi * freqs[r] * (tt + x * col_t))
        out[x * spc:(x + 1) * spc] = seg
    out = out / (np.max(np.abs(out)) + 1e-9) * 0.8
    pcm = (out * 32767).astype("<i2")
    with wave.open(os.path.join(cdir(cid), "tower_recording.wav"), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(pcm.tobytes())
    wtext(cid, "note.txt", "Intercepted tower audio. It sounds like noise. Look, don't just listen.\n")


# ---------------------------------------------------------------- s05 zbarimg (QR)
def c_qr():
    cid = "s05-zbarimg-qr"
    fl = "AVIANS{scan_me_if_you_can}"
    flag(cid, fl)
    payload = base64.b64encode(fl.encode()).decode()   # one extra decode step
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    qimg = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    # drop the QR into a corner of a larger "luggage tag" image
    bg = Image.new("RGB", (640, 420), (235, 231, 220))
    d = ImageDraw.Draw(bg)
    d.rectangle([0, 0, 639, 60], fill=(180, 40, 40))
    d.text((16, 16), "AVIANS BAGGAGE TAG  -  EBBR", fill=(255, 255, 255), font=font(28))
    d.text((20, 120), "PNR: 7K2Q9X", fill=(20, 20, 20), font=font(26))
    d.text((20, 160), "SEQ: 0042", fill=(20, 20, 20), font=font(26))
    bg.paste(qimg, (640 - qimg.size[0] - 20, 420 - qimg.size[1] - 20))
    bg.save(os.path.join(cdir(cid), "baggage_tag.png"))
    wtext(cid, "note.txt", "Scan the code on the tag. What it holds still needs one more decode.\n")


# ---------------------------------------------------------------- s06 xxd / pngcheck (corrupted PNG)
def _text_png(text, w, h, bg=(10, 20, 40), fg=(240, 240, 240)):
    im = Image.new("RGB", (w, h), bg)
    d = ImageDraw.Draw(im)
    d.text((10, h // 2 - 16), text, fill=fg, font=font(28))
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def c_corrupt_png():
    cid = "s06-corrupt-png"
    fl = "AVIANS{fixed_the_broken_wing}"
    flag(cid, fl)
    good = _text_png(fl, 560, 120, (12, 16, 28), (120, 230, 170))
    bad = bytearray(good)
    # break the 8-byte PNG signature (first byte) so viewers refuse it
    bad[0] = 0x00          # should be 0x89
    bad[1] = 0x51          # should be 0x50 'P'
    wbin(cid, "status_screen.png", bytes(bad))
    wtext(cid, "note.txt", "This screenshot won't open - the file header is damaged.\n"
          "A healthy PNG starts with the magic bytes 89 50 4E 47 0D 0A 1A 0A.\n"
          "Repair the header in a hex editor and the image will render.\n")


# ---------------------------------------------------------------- s07 openssl
def _evp_pbkdf2(password, salt, klen, ilen, iters=10000):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters, klen + ilen)
    return dk[:klen], dk[klen:klen + ilen]


def c_openssl():
    cid = "s07-openssl-enc"
    fl = "AVIANS{openssl_enc_decrypted}"
    flag(cid, fl)
    pw = "turbine123"   # in the aviation wordlist
    salt = bytes(random.randrange(256) for _ in range(8))
    key, iv = _evp_pbkdf2(pw, salt, 32, 16)
    pt = (fl + "\n").encode()
    pad = 16 - (len(pt) % 16)
    pt += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    blob = b"Salted__" + salt + ct
    wbin(cid, "secret.enc", blob)
    wtext(cid, "note.txt", "Encrypted with OpenSSL (AES-256-CBC, PBKDF2). The passphrase is a weak,\n"
          "aviation-flavoured word that is in the provided wordlist. Brute it with openssl.\n")


# ---------------------------------------------------------------- s08 john sha512crypt
def c_sha512crypt():
    cid = "s08-john-shadow"
    fl = "AVIANS{shadow_of_the_tower}"
    flag(cid, fl)
    pw = "contrail2026"
    h = sha512_crypt.using(rounds=5000, salt="EBBRtwr1").hash(pw)
    lines = [
        "root:$6$notcrackable$" + "x" * 86 + ":19700:0:99999:7:::",
        f"towerop:{h}:19950:0:99999:7:::",
        "daemon:*:19000:0:99999:7:::",
    ]
    wtext(cid, "shadow", "\n".join(lines) + "\n")
    wtext(cid, "note.txt", "A shadow file from the tower workstation. One account has a crackable password.\n"
          "The flag is AVIANS{that_password} once you recover it.\n")
    # fix: flag IS the password-derived phrase, so store accordingly
    flag(cid, "AVIANS{" + pw + "}")


# ---------------------------------------------------------------- s09 hashid + crack
def c_hashid():
    cid = "s09-hashid-crack"
    pw = "albatross7"
    fl = "AVIANS{" + pw + "}"
    flag(cid, fl)
    h = hashlib.sha1(pw.encode()).hexdigest()
    wtext(cid, "mystery.hash", h + "\n")
    wtext(cid, "note.txt", "An unknown hash dumped from a device. Identify the algorithm first,\n"
          "then crack it. The flag is AVIANS{recovered_password}.\n")


# ---------------------------------------------------------------- s10 radare2 serial check
def _xorflag_c(name, fl, key=0x5A):
    enc = bytes(b ^ key for b in fl.encode()) + b"\x00"
    arr = ",".join(str(b) for b in enc)
    return f"unsigned char {name}[] = {{{arr}}};", key


def c_radare():
    cid = "s10-radare2-serial"
    fl = "AVIANS{radare_reads_the_serial}"
    flag(cid, fl)
    decl, key = _xorflag_c("fe", fl)
    # serial check: 12 chars; sum == K1, xor == K2, s[3]*s[7] low byte == K3
    serial = "AV26-7X3K-Qp9"
    s = serial.encode()
    K1 = sum(s) & 0xFFFF
    K2 = 0
    for c in s:
        K2 ^= c
    K3 = (s[3] * s[7]) & 0xFF
    src = f"""#include <stdio.h>
#include <string.h>
{decl}
int valid(const char*s){{
  if(strlen(s)!={len(serial)}) return 0;
  int sum=0,x=0; for(int i=0;i<{len(serial)};i++){{sum+=(unsigned char)s[i];x^=(unsigned char)s[i];}}
  if(sum!={K1}) return 0;
  if(x!={K2}) return 0;
  if(((unsigned char)s[3]*(unsigned char)s[7]&0xFF)!={K3}) return 0;
  return 1;
}}
int main(){{
  char b[64]; printf("Avionics license key: ");
  if(!fgets(b,sizeof b,stdin)) return 1; b[strcspn(b,"\\n")]=0;
  if(valid(b)){{ for(int i=0;fe[i];i++) putchar(fe[i]^{key}); putchar('\\n'); }}
  else printf("Invalid key.\\n");
  return 0;
}}
"""
    _compile(cid, src, "licensecheck")
    wtext(cid, "note.txt", "An avionics licence-key checker. There is no stored key to compare against -\n"
          "it validates with arithmetic. Reverse the checks and craft a key it accepts.\n")


# ---------------------------------------------------------------- s11 ltrace
def c_ltrace():
    cid = "s11-ltrace-strcmp"
    fl = "AVIANS{ltrace_leaked_the_strcmp}"
    flag(cid, fl)
    decl, key = _xorflag_c("fe", fl)
    secret = "zaventem-ramp-42"
    src = f"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>
{decl}
int main(){{
  char b[128];
  char *sec = strdup("{secret}");
  printf("Ramp agent password: ");
  if(!fgets(b,sizeof b,stdin)) return 1; b[strcspn(b,"\\n")]=0;
  if(strcmp(b,sec)==0){{ for(int i=0;fe[i];i++) putchar(fe[i]^{key}); putchar('\\n'); }}
  else printf("Denied.\\n");
  return 0;
}}
"""
    _compile(cid, src, "rampauth")
    wtext(cid, "note.txt", "A ramp-agent auth binary. It compares your input to a secret.\n"
          "Don't reverse the maths - just watch the library calls it makes.\n")


def _compile(cid, src, out):
    d = cdir(cid)
    tmp = os.path.join(d, "_s.c")
    open(tmp, "w").write(src)
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-no-pie", "-w", tmp, "-o", os.path.join(d, out)], check=True)
    os.remove(tmp)


# ---------------------------------------------------------------- s12 pdf-parser
def c_pdf():
    cid = "s12-pdf-stream"
    fl = "AVIANS{deflated_pdf_stream}"
    flag(cid, fl)
    # minimal PDF; object 5 holds a FlateDecode stream with the flag (not rendered)
    hidden = zlib.compress(("Crew briefing - internal only\nFlag: " + fl + "\n").encode())
    objs = []
    objs.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objs.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objs.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] "
                b"/Contents 4 0 R /Resources << >> >>\nendobj\n")
    c4 = b"BT /F1 18 Tf 20 60 Td (Nothing to see on this page.) Tj ET"
    objs.append(b"4 0 obj\n<< /Length %d >>\nstream\n" % len(c4) + c4 + b"\nendstream\nendobj\n")
    objs.append(b"5 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(hidden)
                + hidden + b"\nendstream\nendobj\n")
    pdf = b"%PDF-1.5\n"
    offsets = []
    for o in objs:
        offsets.append(len(pdf))
        pdf += o
    xref = len(pdf)
    pdf += b"xref\n0 %d\n" % (len(objs) + 1)
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += ("%010d 00000 n \n" % off).encode()
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    wbin(cid, "briefing.pdf", pdf)
    wtext(cid, "note.txt", "A one-page PDF that looks empty. Objects can hold compressed streams that\n"
          "never get drawn. Enumerate the objects and inflate the streams.\n")


# ---------------------------------------------------------------- s13 CyberChef Magic (nested)
def c_magic():
    cid = "s13-cyberchef-magic"
    fl = "AVIANS{magic_peels_the_onion}"
    flag(cid, fl)
    step = fl.encode()
    step = codecs.encode(step.decode(), "rot_13").encode()   # ROT13
    step = step.hex().encode()                               # to hex
    step = gzip.compress(step, mtime=0)                      # gzip
    step = base64.b32encode(step)                            # base32
    step = base64.b64encode(step)                            # base64
    out = step.decode()[::-1]                                # reversed
    wtext(cid, "intercept.txt", out + "\n")
    wtext(cid, "note.txt", "A VDL Mode 2 intercept, wrapped in several layers of encoding.\n"
          "Let CyberChef's 'Magic' peel it, or unwrap it by hand.\n")


# ---------------------------------------------------------------- o01 exiftool geolocation
def c_geo():
    cid = "o01-exif-geolocate"
    fl = "AVIANS{EBBR}"   # the ICAO code of the airport at the embedded coordinates
    flag(cid, fl)
    import piexif
    # a plausible apron photo
    im = Image.new("RGB", (480, 320), (120, 150, 185))
    d = ImageDraw.Draw(im)
    d.rectangle([0, 220, 480, 320], fill=(60, 62, 66))          # apron
    d.rectangle([40, 150, 180, 230], fill=(200, 200, 205))      # fuselage
    d.polygon([(180, 170), (300, 150), (180, 205)], fill=(210, 210, 215))  # wing
    d.text((12, 12), "ramp - early morning", fill=(240, 240, 240), font=font(22))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=90)
    # Brussels Airport (EBBR): 50.9014 N, 4.4844 E
    def dms(v):
        v = abs(v); deg = int(v); m = int((v - deg) * 60); s = round((((v - deg) * 60) - m) * 60 * 100)
        return ((deg, 1), (m, 1), (s, 100))
    gps = {
        piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: dms(50.9014),
        piexif.GPSIFD.GPSLongitudeRef: b"E", piexif.GPSIFD.GPSLongitude: dms(4.4844),
    }
    exif = {"0th": {piexif.ImageIFD.Artist: b"F/O k.wouters", piexif.ImageIFD.Make: b"Avians SkyCam"},
            "Exif": {}, "GPS": gps, "1st": {}, "thumbnail": None}
    out = io.BytesIO()
    piexif.insert(piexif.dump(exif), buf.getvalue(), out)
    wbin(cid, "apron_dawn.jpg", out.getvalue())
    wtext(cid, "note.txt", "A crew member posted this 'harmless' apron photo. It carries GPS metadata.\n"
          "Read the coordinates, find the airport, and submit its 4-letter ICAO code as the flag,\n"
          "e.g. AVIANS{XXXX}.\n")


# ---------------------------------------------------------------- o02 web recon / exposed .git
def c_site_recon():
    cid = "o02-site-recon"
    fl = "AVIANS{exposed_dot_git_leaks_secrets}"
    flag(cid, fl)
    root = os.path.join(cdir(cid), "avians-ground-services")
    if os.path.isdir(root):
        shutil.rmtree(root)
    os.makedirs(os.path.join(root, "private-backup"))
    with open(os.path.join(root, "index.html"), "w") as f:
        f.write("<!doctype html><title>Avians Ground Services</title>\n"
                "<h1>Avians Ground Services</h1><p>Fuel, towing, de-icing at EBBR.</p>\n"
                "<!-- TODO @m.devops: the old deploy backup is still under /private-backup, clean it up -->\n")
    with open(os.path.join(root, "robots.txt"), "w") as f:
        f.write("User-agent: *\nDisallow: /private-backup/\nDisallow: /tiles/\n")
    # build a tiny git repo whose history leaks a secret that was later 'removed'
    bk = os.path.join(root, "private-backup")
    env = dict(os.environ, GIT_AUTHOR_NAME="m.devops", GIT_AUTHOR_EMAIL="m.devops@avians.local",
               GIT_COMMITTER_NAME="m.devops", GIT_COMMITTER_EMAIL="m.devops@avians.local",
               GIT_AUTHOR_DATE="2026-02-10T09:00:00", GIT_COMMITTER_DATE="2026-02-10T09:00:00")
    def g(*a):
        subprocess.run(["git", "-C", bk, *a], env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    g("init", "-q")
    g("config", "user.name", "m.devops")
    g("config", "user.email", "m.devops@avians.local")
    with open(os.path.join(bk, "deploy.sh"), "w") as f:
        f.write("#!/bin/sh\n# deploy script\nAPI_TOKEN=\"" + fl + "\"\ncurl -H \"Authorization: $API_TOKEN\" https://ops.avians.local/deploy\n")
    g("add", "-A"); g("commit", "-q", "-m", "add deploy script")
    env2 = dict(env, GIT_AUTHOR_DATE="2026-02-11T11:00:00", GIT_COMMITTER_DATE="2026-02-11T11:00:00")
    with open(os.path.join(bk, "deploy.sh"), "w") as f:
        f.write("#!/bin/sh\n# deploy script\nAPI_TOKEN=\"$DEPLOY_TOKEN\"   # moved to env var\ncurl -H \"Authorization: $API_TOKEN\" https://ops.avians.local/deploy\n")
    subprocess.run(["git", "-C", bk, "add", "-A"], env=env2, check=True)
    subprocess.run(["git", "-C", bk, "commit", "-q", "-m", "stop hardcoding the api token"], env=env2,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # remove the working-tree scripts clutter but KEEP .git (the point of the challenge)
    # package the whole mirror (including .git) as a tarball: a nested .git can't
    # live loose inside the outer repo, and a single archive is what you'd 'mirror'.
    import tarfile
    tgz = os.path.join(cdir(cid), "mirror.tar.gz")
    with tarfile.open(tgz, "w:gz") as t:
        t.add(root, arcname="avians-ground-services")
    shutil.rmtree(root)
    wtext(cid, "note.txt", "You mirrored a small public site (extract mirror.tar.gz).\n"
          "The current files look clean - but recon is about what's left behind.\n"
          "Check robots.txt, then dig. (The flag was committed once and 'removed' later;\n"
          "git history remembers. Tools: git log/show, or gitleaks/trufflehog.)\n")


# ---------------------------------------------------------------- build
def main():
    if os.path.isdir(OUT):
        for d in os.listdir(OUT):
            if d != "_shared":
                shutil.rmtree(os.path.join(OUT, d))
    os.makedirs(OUT, exist_ok=True)
    c_tshark(); c_binwalk(); c_zsteg(); c_spectrogram(); c_qr(); c_corrupt_png()
    c_openssl(); c_sha512crypt(); c_hashid(); c_radare(); c_ltrace(); c_pdf(); c_magic()
    c_geo(); c_site_recon()

    hashes = {cid: hashlib.sha256(v.strip().lower().encode()).hexdigest() for cid, v in FLAGS.items()}
    pdir = os.path.join(ROOT, "kali-tools", "portal")
    os.makedirs(pdir, exist_ok=True)
    with open(os.path.join(pdir, "flags.js"), "w") as f:
        f.write("// SHA-256 of lower-cased flags. No plaintext.\n")
        f.write("window.FLAG_HASHES = " + json.dumps(hashes, indent=2) + ";\n")
    sdir = os.path.join(ROOT, "kali-tools", "solutions")
    os.makedirs(sdir, exist_ok=True)
    with open(os.path.join(sdir, "FLAGS_SPOILERS.txt"), "w") as f:
        f.write("SPOILERS - Season 2 flags\n\n" + "\n".join(f"{k}: {v}" for k, v in FLAGS.items()) + "\n")
    print("Built", len(FLAGS), "challenges into", OUT)
    for k, v in FLAGS.items():
        print("  ", k, "->", v)


if __name__ == "__main__":
    main()
