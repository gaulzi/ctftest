# OSINT field guide (for people who've never done it)

OSINT = **Open-Source Intelligence**: finding things out using only public
information — no hacking, no logins you weren't given. In a CTF it usually means
"here's a photo / username / document / domain — find the hidden fact." The
organisers said there'll be a lot of it, so this guide gets you from zero to
competent. It leans aviation because that's your event.

## The mindset

1. **Start from what you're given and pivot.** A photo → its metadata → a location → an airport → a flight → a tail number → an owner. Each fact is a lever to the next.
2. **Write everything down.** A scratch doc of every username, email, domain, coordinate, timestamp. Connections appear when you see them side by side.
3. **Primary sources beat guesses.** Confirm on the actual registry / map / capture, don't assume.
4. **Stay in scope and legal.** OSINT is passive — reading public data. Don't log into anything, don't social-engineer real people, don't touch systems. In a CTF, only use the provided material and public reference sites.

## The core toolkit (all on Kali or in a browser)

**Metadata & images**
- `exiftool <file>` — the single most useful OSINT command. GPS, camera, author, software, timestamps on photos; author/producer on PDFs and Office docs. *Challenge: o01.*
- Reverse image search — Google Lens, Yandex (best for places/faces), TinEye. Find where else an image appears, or what a landmark is.
- Geolocation — drop coordinates on OpenStreetMap / Google Maps; use shadows, signage, road markings, aircraft liveries and runway numbers as clues.

**People, usernames, emails**
- `sherlock <username>` — checks a username across 300+ sites.
- `holehe <email>` — which sites have an account for that email.
- Have I Been Pwned (haveibeenpwned.com) — which breaches an email appears in.
- `theHarvester -d <domain> -b all` — emails, names, subdomains for a domain.

**Domains, sites, infrastructure**
- `whois <domain>` / `dig <domain> any` — ownership and DNS records.
- `dnsrecon -d <domain>` / `dnsenum` / `sublist3r` — enumerate subdomains.
- **crt.sh** (certificate transparency) — paste a domain, get every TLS cert ever issued → hidden subdomains.
- **Wayback Machine** (web.archive.org) — old versions of a page; deleted content, exposed files.
- `robots.txt`, `/sitemap.xml`, exposed `.git` — what a site tried to hide. *Challenge: o02.*
- `recon-ng` / `spiderfoot` — frameworks that automate a lot of the above.
- **Google dorking** — `site:`, `filetype:pdf`, `intitle:`, `inurl:`, `"exact phrase"`, `-exclude`. e.g. `site:avians.example filetype:xlsx`.
- **Shodan / Censys** — search the internet's exposed services by banner, port, org, location.

## Aviation OSINT — the part that's specific to your event

This is a whole discipline and it's very "Googleable" once you know the sites and the vocabulary.

**Identifiers to know**
- **ICAO airport code** = 4 letters (EBBR = Brussels, EGLL = Heathrow). **IATA** = 3 letters (BRU, LHR).
- **ICAO 24-bit address** = a hex id burned into each aircraft's transponder (e.g. `44xxxx` = Belgium). Maps 1:1 to a **registration** (tail number, e.g. `OO-SNA`).
- **Callsign** = what ATC calls the flight (e.g. `BEL123`), *not* the same as the registration.
- **Registration prefixes**: `OO-`=Belgium, `G-`=UK, `D-`=Germany, `F-`=France, `N`=USA, `PH-`=Netherlands.

**Where to look (all free in a browser)**
- **Flightradar24**, **ADS-B Exchange** (adsbexchange.com — the unfiltered one, keeps history), **FlightAware**, **OpenSky Network** (free API + historical data) — track a flight live or in the past by callsign, registration or ICAO hex.
- **planespotters.net**, **jetphotos.com** — registration → photos, type, operator, history. Great for "what is this aircraft."
- **National registries** — e.g. the FAA N-number registry (USA), national CAA databases — registration → owner.
- **airnav / airport charts / SkyVector** — airport diagrams, runway headings, approach plates. Useful to geolocate an apron photo or identify a runway in a picture.
- **NOTAM** search, **METAR/TAF** (aviationweather.gov) — notices and weather, sometimes needed to pin a time.

**Typical aviation-OSINT challenge shapes**
- "Here's a photo of a parked aircraft — what's the registration / who operates it / where was it taken?" → read the tail, planespotters it, exiftool the file, geolocate the apron.
- "Flight X flew an unusual route on date Y — where did it go?" → ADS-B Exchange / OpenSky history by callsign.
- "This ICAO hex was squawking 7700 — identify the aircraft." → hex → registration → type/owner.
- "Find the airport in this cockpit/approach photo." → runway number + surroundings + charts.

## A repeatable workflow

1. **Inventory** what you're given and run the obvious tool (`exiftool` on any file, `whois`/`crt.sh` on any domain, planespotters on any tail).
2. **Extract** every identifier (coords, usernames, emails, domains, tail numbers, timestamps) into your notes.
3. **Pivot** each one on the matching site above.
4. **Cross-check** two independent sources before you commit a flag.
5. **Record the path** — the organisers often want *how* you found it, not just the answer.

## Practice here first

- **o01 – Apron Photo**: `exiftool` → coordinates → airport ICAO. The whole photo-OSINT loop in one go.
- **o02 – Left Behind**: `robots.txt` → exposed `.git` → `git log` / `gitleaks`. The whole web-recon loop in one go.

Do those two, then spend an evening *using the real sites above on real aircraft* — pick a plane overhead on ADS-B Exchange and chase it to its owner. That hour will do more than any amount of reading.

## Ethics / scope reminder

Everything here is passive reading of public data, which is fine. Do **not** cross into logging in, contacting people, probing systems, or pulling private records — that's not OSINT and it's not in scope. Keep it to the challenge material and the public reference sites.
