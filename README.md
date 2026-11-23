# Avians Flight Deck — practice CTF

A self-contained, aviation-themed practice range to warm up for the Brussels CTF.
It is built for a **mixed team** (blue team, offensive, reverse engineering, forensics, CTI):
22 challenges across six areas, each with a briefing, the exact tools to reach for,
what you are meant to learn, tiered hints, and a full walkthrough for when you are stuck.

Flags look like `AVIANS{...}`. The web portal checks them locally in your browser
(SHA-256 against `portal/flags.js`), so no server or internet is needed to play.

## Run it locally (recommended for practice)

From the repository root:

```bash
python3 -m http.server 8000
```

Then open **http://localhost:8000/portal/** in a browser. File downloads, hints and
flag-checking all work. This is the best way to use it on a Kali laptop.

## Live preview

An interactive preview is published as a Claude artifact (UX + hints + flag-checking work;
file *downloads* only work on a real web server because the artifact sandbox blocks them):
https://claude.ai/artifact/3T6cctTe4M53SHjMHhmGDY

To host it at **ctf.1337.is** on Cloudflare, see [docs/DEPLOY.md](docs/DEPLOY.md).

## Where to start

1. Read [docs/KALI_SETUP.md](docs/KALI_SETUP.md) — install the tools once, in a VM.
2. Read [docs/EVENT_PREP.md](docs/EVENT_PREP.md) — what a mixed CTF is like and how a team of 4 splits the work.
3. Open the portal and start with the **Pre-flight** category.

## Layout

```
portal/            the web portal (index.html + data.js + flags.js)
challenges/        one folder per challenge, with the evidence files
  _shared/         aviation_wordlist.txt used by the cracking challenges
  avians-ctf-pack.zip   everything zipped, for easy transfer to a VM
generator/         scripts that build every challenge file (build.py)
solutions/         FLAGS_SPOILERS.txt — all answers. Do NOT deploy this folder.
docs/              setup, event-prep and deployment guides
```

## Regenerating the challenge files

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pyModeS
python3 generator/build.py
```

This rewrites everything under `challenges/`, `portal/flags.js` and `solutions/`.
`build.py` contains every flag in plain text, so treat it like the solutions file.

## A note on scope

Everything here is fictional training data on a self-contained range. The techniques
are the standard, dual-use skills a CTF exercises: packet and log analysis, decoding,
signal decoding, password cracking against a provided wordlist, malware triage and
detection engineering. Use them on this range and on systems you are authorized to test.
