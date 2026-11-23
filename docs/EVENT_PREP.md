# What to expect, and how a team of 4 works a CTF

You are new to this, so here is the shape of the thing and a game plan. None of it is
secret knowledge — it is mostly about not wasting time on event day.

## The format you described

- **Teams of 4**, experts from mixed disciplines (blue team, CTI, offensive, reverse
  engineering, forensics). You bring a laptop able to run a VM. No fee; you cover travel.
- That line-up almost always means a **Jeopardy-style CTF**: a board of independent
  challenges grouped by category and point value, you solve what you can in a fixed window,
  highest score wins. (The other style, *attack–defence*, where you patch and hack live
  services, is less common for a one-day mixed event — but the defensive instincts below
  help there too.)
- "Aviation-themed" usually means the *story and data* are aviation (ADS-B, ACARS,
  airport IT, OT/SCADA for baggage and fuel), while the *skills* are ordinary CTF skills.
  That is exactly how this practice range is built.

## How four people cover a board

Don't all stare at the same challenge. Split by strength, then regroup:

| Role on your team | Takes the lead on | Maps to these practice categories |
|---|---|---|
| **Forensics / blue** | pcaps, disk/file artifacts, logs | Network, Logs, Forensics |
| **Offensive** | web (SQLi), cracking, exploitation, scanning | Logs (SQLi), Forensics (cracking), Network (scan) |
| **Reverse engineering** | binaries, obfuscated scripts, malware | Hunt / RE |
| **CTI / generalist** | triage, YARA, OSINT, the aviation-specific puzzles, coordination | Aviation, Hunt / RE |

Practical rules that win points:

1. **Read the whole board first (5 minutes).** Note the cheap challenges and anything in
   your wheelhouse. Pick low-hanging fruit early to get on the scoreboard and settle nerves.
2. **One shared notes doc.** Flags submitted, who is on what, dead ends. Avoids two people
   solving the same thing and nobody touching another.
3. **Timebox.** If a challenge eats 30–40 minutes with no progress, park it and move on.
   Come back with fresh eyes or a teammate.
4. **Submit carefully.** Flag format matters. Many platforms limit wrong submissions.
   Copy–paste, don't retype. Watch for `l`/`1`/`I` and `O`/`0`.
5. **The flag format is your friend.** Here it is `AVIANS{...}`. At the event it will be
   something like `flag{...}` or `CTF{...}`. `grep -r 'flag{' .` on any evidence is a
   legitimate, fast first move.

## The mental moves that solve most challenges

- **Identify before you analyse.** `file`, `strings`, `exiftool`, `binwalk` on anything
  unknown. Half of "forensics" is realising a file is not what its name claims.
- **Follow the conversation.** In a pcap, Follow TCP Stream turns packets into a readable
  chat. Clear-text protocols (FTP, HTTP, Telnet, ACARS) hand you the answer.
- **Count things.** `sort | uniq -c | sort -rn` finds the one weird line among thousands:
  the attacker IP, the odd DNS name, the message that appears only once.
- **Decode, don't despair.** Base64, hex, URL-encoding, ROT13 are *encodings*, not
  encryption. CyberChef's "Magic" will often guess the chain for you.
- **Plausibility is a weapon** (the aviation signals especially). A Cessna at Mach 1, a
  GPS position that jumps 300 km, a callsign with no flight plan — anomalies are the flag.
- **Never run unknown code to "see what it does."** Read it statically. If you must
  detonate, do it in a snapshot VM with networking off. (This is a graded skill here —
  see the Baggage Dropper challenge.)

## Aviation facts worth knowing cold

- **Emergency squawks:** 7500 = hijack, 7600 = radio failure, 7700 = general emergency.
- **ADS-B is unauthenticated** — anyone can transmit; spoofing is real. Messages are 112-bit
  Mode S; a bad CRC = noise, ignore it.
- **ACARS / VDL is mostly clear text.** Treat anything sent over it as public.
- **GNSS spoofing/jamming** is an active, real-world problem over parts of Europe; the tells
  are sudden position jumps, impossible speeds, and suspiciously perfect signal.
- **OT ports** you might meet: 502 Modbus, 102 S7, 20000 DNP3, 44818 EtherNet/IP, 47808 BACnet.

## A realistic warm-up schedule for the week

- **Day 1–2:** Build the VM (KALI_SETUP.md), do all **Pre-flight** + **Forensics** challenges.
- **Day 3:** **Network** category. Get comfortable in Wireshark: filters, Follow Stream,
  Export Objects, Statistics → Conversations.
- **Day 4:** **Logs** category. Live in `grep/awk/sort/uniq/jq`.
- **Day 5:** **Aviation** category. Set up pyModeS; learn to read ADS-B and NMEA.
- **Day 6:** **Hunt / RE** category. YARA, obfuscation, persistence hunting.
- **Day 7:** Redo anything that fought you, *without* hints, against the clock. Pair up
  the way you will on event day.

You do not need to be fast yet. You need the tools installed, the muscle memory for
`file`/`strings`/`grep`/Wireshark, and no surprises on the day. That is the whole point
of this range.
