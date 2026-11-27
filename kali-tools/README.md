# HostBusters Kali Toolbox (Season 2)

A harder follow-up to the Season 1 range, organised around **the Kali tools themselves**.
Every challenge exists to teach one tool you'd actually reach for in a mixed CTF — the
portal shows the tool as a green badge — with fewer hints than Season 1 and a dedicated
**OSINT** track because the organisers say there'll be a lot of it.

Lives on the `claude/aviation-ctf-kali-tools` branch so the Season 1 site is untouched.

## Run it locally

From the repository root:

```bash
python3 -m http.server 8000
```

Open **http://localhost:8000/kali-tools/portal/**. Download files, work in your Kali VM,
submit flags (checked locally in your browser; nothing leaves the page).

## The 15 challenges and the tool each one teaches

| Category | Challenge | Tool you learn |
|---|---|---|
| OSINT | Apron Photo | `exiftool` (GPS → airport ICAO) |
| OSINT | Left Behind | exposed `.git` → `git log` / `gitleaks` |
| Network | Carried Off | `tshark --export-objects` (+ `fcrackzip`) |
| Forensics | Flash Dump | `binwalk` / `foremost` carving |
| Forensics | Baggage Tag | `zbarimg` (QR → base64) |
| Forensics | Broken Screenshot | `xxd` / `hexedit` / `pngcheck` (fix magic bytes) |
| Forensics | Empty Briefing | `pdf-parser` / `pdfid` (inflate a hidden stream) |
| Stego | Least Significant | `zsteg` (LSB) |
| Stego | Tower Recording | `sox` / Audacity (spectrogram) |
| Crypto | Sealed Orders | `openssl enc` (brute a weak passphrase) |
| Crypto | Wrapped Intercept | CyberChef "Magic" (nested encodings) |
| Passwords | Shadow of the Tower | `john` (sha512crypt) |
| Passwords | Unknown Hash | `hashid` → `hashcat`/`john` |
| Reversing | Licence Key | `radare2` / Ghidra (constraint-based keygen) |
| Reversing | Ramp Auth | `ltrace` (leak a strcmp) |

New to OSINT? Read **[docs/OSINT_GUIDE.md](docs/OSINT_GUIDE.md)** first — it covers the
mindset, the Kali OSINT tools, and aviation-specific sources (ADS-B Exchange, OpenSky,
planespotters, ICAO/registration lookups).

## Extra tools you'll need in your VM

Most ship with Kali. A few aren't in the default metapackage:

```bash
sudo apt install -y zsteg sox fcrackzip pdf-parser pdfid gitleaks radare2 ltrace \
                    libimage-exiftool-perl zbar-tools
# zsteg is a Ruby gem on some images: sudo gem install zsteg
```

## Regenerating

```bash
python3 generator/build_kali.py
```

Needs `gcc` (for the two reversing binaries) and Python packages `numpy pillow qrcode
passlib piexif cryptography`. The generator rewrites `kali-tools/challenges/`,
`kali-tools/portal/flags.js` and `kali-tools/solutions/` (spoilers — don't ship publicly
if you want the flags protected).

## What's not here yet: the live lab

The iconic *live-target* tools — `nmap`, `gobuster`/`ffuf`, `sqlmap`, `hydra` — need a
running, deliberately-vulnerable target, which can't be a static download. That belongs
in a container you run locally (or on k3s), never exposed to the internet. Ask and a small
Docker lab can be added under `kali-tools/lab/`.
