// Kali Toolbox (Season 2) catalogue. Each challenge spotlights a Kali tool.
// Files live under ../challenges/<id>/ when served from a web server.
window.SEASON = "Kali Toolbox";
window.CATEGORIES = [
  { id:"osint",     name:"OSINT",       blurb:"Open-source intelligence: metadata, geolocation, and what people leave behind." },
  { id:"network",   name:"Network",     blurb:"Packet captures: carve files and follow conversations." },
  { id:"forensics", name:"Forensics",   blurb:"Carving, file repair, document internals." },
  { id:"stego",     name:"Stego",       blurb:"Data hidden in images and audio." },
  { id:"crypto",    name:"Crypto / Encoding", blurb:"Peel encodings and break weak encryption." },
  { id:"password",  name:"Passwords",   blurb:"Identify and crack hashes." },
  { id:"reversing", name:"Reversing",   blurb:"Static and dynamic analysis of binaries." }
];

// tool = the headline Kali tool this challenge is here to teach.
window.CHALLENGES = [
{
  id:"o01-exif-geolocate", cat:"osint", tool:"exiftool", title:"Apron Photo", diff:1, points:100,
  files:["apron_dawn.jpg","note.txt"],
  story:"A crew member posted a 'harmless' apron photo. Phones stamp photos with GPS, and GPS gives away airports.",
  question:"Read the photo's coordinates, find the airport, and submit its 4-letter ICAO code: HOSTBUSTERS{XXXX}.",
  tools:[
    {name:"exiftool", why:"Reads every metadata tag, GPS included.", cmd:"exiftool apron_dawn.jpg"},
    {name:"a map", why:"Turn lat/long into a place. OpenStreetMap or Google Maps.", cmd:"paste '50.9014, 4.4844' into the search box"},
    {name:"ICAO lookup", why:"Airports have 4-letter ICAO and 3-letter IATA codes.", cmd:"which major airport is at those coordinates?"}
  ],
  learn:"The first move of photo OSINT is always metadata. `exiftool` dumps GPSLatitude/GPSLongitude (and often the camera, owner and timestamps). Drop the coordinates on a map; here they land on a well-known European hub. Airports are identified by ICAO (4 letters, e.g. EBBR) and IATA (3 letters, e.g. BRU) codes — the flag wants the ICAO.",
  hints:["exiftool apron_dawn.jpg — look at the GPS Position line.","Put the latitude/longitude into any map. What airport is it?","It's Brussels Airport. Its ICAO code is the flag."],
  solve:"exiftool -gpslatitude -gpslongitude -artist apron_dawn.jpg\n# 50.9014 N, 4.4844 E = Brussels Airport = ICAO EBBR  ->  HOSTBUSTERS{EBBR}"
},
{
  id:"o02-site-recon", cat:"osint", tool:"git / gitleaks", title:"Left Behind", diff:2, points:175,
  files:["mirror.tar.gz","note.txt"],
  story:"You mirrored a small public site. The live files look clean — but OSINT is about what got left behind: robots.txt, backups, and version-control folders that were never meant to ship.",
  question:"Dig through the mirror and recover the API token that was committed and later 'removed'.",
  tools:[
    {name:"robots.txt", why:"Lists paths the owner would rather you didn't visit — a map of what's hidden.", cmd:"cat hostbusters-ground-services/robots.txt"},
    {name:"git", why:"An exposed .git folder is the whole history. 'Removed' secrets still live in old commits.", cmd:"git -C <dir> log -p   /   git show <oldcommit>"},
    {name:"gitleaks / trufflehog", why:"Scan a repo's whole history for secrets automatically.", cmd:"gitleaks detect --source <dir>"}
  ],
  learn:"Web recon is reading the leftovers. `robots.txt` points at a backup folder; inside is an exposed `.git` directory (a classic real-world leak). Deleting a secret in a new commit does NOT remove it — it's still in history. `git log -p`, `git show <commit>`, or an automated scanner (gitleaks) recovers it. On a live target you'd mirror the .git first with git-dumper, then do exactly this.",
  hints:["tar xzf mirror.tar.gz; read robots.txt. Where does it tell you not to look?","That folder contains a .git directory. Run: git -C .../private-backup log --oneline","The latest commit 'removed' the token. git show the commit before it — or just git log -p."],
  solve:"tar xzf mirror.tar.gz && cd hostbusters-ground-services/private-backup\ngit log --oneline\ngit log -p | grep -i api_token        # the token is in the first commit\n# or: gitleaks detect --source . "
},
{
  id:"s01-tshark-exfil", cat:"network", tool:"tshark / Wireshark", title:"Carried Off", diff:2, points:150,
  files:["capture.pcap","note.txt"],
  story:"A file was pulled off the ops server over plain HTTP. The capture has it — you just have to rebuild it, and it's locked.",
  question:"Carve the transferred file out of the capture, open it, and read the flag.",
  tools:[
    {name:"tshark --export-objects", why:"Reassembles files sent over HTTP straight out of a pcap.", cmd:"tshark -r capture.pcap --export-objects http,out"},
    {name:"Wireshark", why:"File → Export Objects → HTTP does the same with a click; Follow TCP Stream to eyeball it.", cmd:"File → Export Objects → HTTP"},
    {name:"fcrackzip / zip2john+john", why:"The carved file is a password ZIP; crack it with the aviation wordlist.", cmd:"fcrackzip -D -p ../_shared/aviation_wordlist.txt -u payload.zip"}
  ],
  learn:"Two-step network forensics: first recover the artifact, then deal with it. `--export-objects http,<dir>` rebuilds every file transferred over HTTP in the capture. Here it's a password-protected ZIP, so you pivot to cracking (same wordlist muscle as the password challenges). Real DFIR is this chain: extract, then analyse.",
  hints:["tshark -r capture.pcap --export-objects http,out  (then look in out/)","It's a ZIP and it's password-protected. Crack it with the shared aviation wordlist.","fcrackzip -D -p challenges/_shared/aviation_wordlist.txt -u out/payload.zip"],
  solve:"tshark -r capture.pcap --export-objects http,out\nfcrackzip -D -p ../_shared/aviation_wordlist.txt -u out/payload.zip   # pw: cockpit1\nunzip -P cockpit1 out/payload.zip && cat secret_route.txt"
},
{
  id:"s02-binwalk-carve", cat:"forensics", tool:"binwalk / foremost", title:"Flash Dump", diff:2, points:150,
  files:["recovered.img","note.txt"],
  story:"A raw image pulled from a dashboard flash chip. Several files are packed into it at different offsets.",
  question:"Carve out the embedded files and read the flag from the one that matters.",
  tools:[
    {name:"binwalk", why:"Scans for embedded file signatures and shows their offsets.", cmd:"binwalk recovered.img"},
    {name:"binwalk -e / --dd", why:"Extract everything it recognised.", cmd:"binwalk -e recovered.img"},
    {name:"foremost / scalpel", why:"Signature-based carving as an alternative extractor.", cmd:"foremost -i recovered.img -o out"}
  ],
  learn:"Firmware and disk dumps are many files concatenated with junk between them. `binwalk` finds them by magic bytes and prints offsets; `-e` extracts. When auto-extraction misses one, carve it by hand with `dd skip=<offset>`, or let `foremost` recover by signature. One of the embedded files is a ZIP with the flag.",
  hints:["binwalk recovered.img — note the Zip archive entry and its offset.","binwalk -e recovered.img, then look in the _recovered.img.extracted folder.","If -e is stubborn: dd if=recovered.img bs=1 skip=<offset> of=out.zip, then unzip."],
  solve:"binwalk recovered.img\nbinwalk -e recovered.img\ncat _recovered.img.extracted/*/flag.txt 2>/dev/null || find _recovered.img.extracted -name '*.txt' -exec cat {} +"
},
{
  id:"s03-zsteg-lsb", cat:"stego", tool:"zsteg", title:"Least Significant", diff:2, points:175,
  files:["approach_chart.png","note.txt"],
  story:"An ordinary-looking chart thumbnail. The least-significant bits of the pixels are carrying a message.",
  question:"Extract the hidden text from the image's LSBs.",
  tools:[
    {name:"zsteg", why:"The go-to for LSB stego in PNG/BMP; tries every bit/channel order.", cmd:"zsteg -a approach_chart.png"},
    {name:"stegsolve", why:"GUI: step through bit planes and channels visually.", cmd:"java -jar stegsolve.jar"},
    {name:"zsteg -E", why:"Once you know the channel, extract that payload directly.", cmd:"zsteg -E 'b1,rgb,lsb,xy' approach_chart.png"}
  ],
  learn:"LSB steganography flips the lowest bit of each colour channel to store data — invisible to the eye. `zsteg -a` brute-forces the common encodings (bit depth, channel order, pixel direction) and prints anything that looks like text. The hit here is the standard `b1,rgb,lsb,xy`: bit 1, R→G→B, LSB-first, row-major.",
  hints:["zsteg -a approach_chart.png and scan the output for readable ASCII.","The payload is in the b1,rgb,lsb,xy channel.","zsteg -E 'b1,rgb,lsb,xy' approach_chart.png"],
  solve:"zsteg -a approach_chart.png   # look for the HOSTBUSTERS{...} line\n# or: zsteg -E 'b1,rgb,lsb,xy' approach_chart.png"
},
{
  id:"s04-spectrogram", cat:"stego", tool:"sox / Audacity", title:"Tower Recording", diff:2, points:175,
  files:["tower_recording.wav","note.txt"],
  story:"Intercepted tower audio. Played back it's just noise — because the message is written in the frequencies, not the sound.",
  question:"View the audio's spectrogram and read the flag.",
  tools:[
    {name:"Audacity", why:"Open the WAV, switch the track to Spectrogram view, read the text.", cmd:"audacity tower_recording.wav  (Track menu → Spectrogram)"},
    {name:"sox", why:"Render a spectrogram image from the command line.", cmd:"sox tower_recording.wav -n spectrogram -o spec.png"},
    {name:"spek / ffmpeg", why:"Quick spectral viewers if Audacity isn't handy.", cmd:"ffmpeg -i tower_recording.wav -lavfi showspectrumpic=s=1024x512 spec.png"}
  ],
  learn:"Audio stego often hides text in the frequency domain: the waveform is meaningless, but a spectrogram (frequency vs. time) draws the letters. `sox ... -n spectrogram` or Audacity's spectrogram view reveals it. The same view also exposes hidden DTMF tones and SSTV images — always look at unknown audio, don't just listen.",
  hints:["Don't listen — look. Make a spectrogram.","sox tower_recording.wav -n spectrogram -o spec.png  (then open spec.png)","In Audacity: click the track name → Spectrogram. The flag is drawn across the frequencies."],
  solve:"sox tower_recording.wav -n spectrogram -o spec.png && xdg-open spec.png\n# the flag text is drawn in the spectrogram"
},
{
  id:"s05-zbarimg-qr", cat:"forensics", tool:"zbarimg", title:"Baggage Tag", diff:1, points:100,
  files:["baggage_tag.png","note.txt"],
  story:"A baggage tag with a QR code in the corner. Scanning it gives you something that still needs one more decode.",
  question:"Scan the QR code and finish decoding what it holds.",
  tools:[
    {name:"zbarimg", why:"Decodes QR/barcodes from an image file on the command line.", cmd:"zbarimg baggage_tag.png"},
    {name:"a phone / online reader", why:"Any QR scanner works if zbar isn't installed.", cmd:"point a camera at it"},
    {name:"base64", why:"The QR's contents are Base64 — one more step.", cmd:"echo '<decoded>' | base64 -d"}
  ],
  learn:"`zbarimg` pulls data straight out of QR and barcodes without a camera — handy when a challenge hands you an image. CTF codes are often double-wrapped (here, Base64 inside the QR), so decode, then look at what you got and decode again. The same tool reads the barcodes you'll meet on boarding passes (PDF417/Aztec).",
  hints:["zbarimg baggage_tag.png","The result isn't the flag yet — it looks like Base64. Decode it.","echo 'QVZJ...' | base64 -d"],
  solve:"zbarimg -q baggage_tag.png | sed 's/QR-Code://' | base64 -d"
},
{
  id:"s06-corrupt-png", cat:"forensics", tool:"xxd / hexedit", title:"Broken Screenshot", diff:1, points:125,
  files:["status_screen.png","note.txt"],
  story:"A status-screen screenshot that no viewer will open — its file header has been damaged. Fix the bytes and the image renders.",
  question:"Repair the PNG header and read the flag off the image.",
  tools:[
    {name:"xxd", why:"Dump the file to hex (and back) to see and fix the header.", cmd:"xxd status_screen.png | head"},
    {name:"hexedit / ghex / vim -b", why:"Edit the raw bytes in place.", cmd:"hexedit status_screen.png"},
    {name:"pngcheck", why:"Tells you exactly what's wrong with a PNG.", cmd:"pngcheck -v status_screen.png"}
  ],
  learn:"Files are recognised by magic bytes, not extensions. A PNG must start with `89 50 4E 47 0D 0A 1A 0A`. Corrupt those and viewers bail — fixing them is a one-byte edit. `pngcheck` diagnoses PNG damage (bad signature, wrong IHDR, CRC errors); `xxd`/`hexedit` apply the fix. Same idea rescues truncated JPEGs and mangled ZIP headers.",
  hints:["xxd status_screen.png | head — compare the first 8 bytes with a healthy PNG signature.","The first two bytes are wrong. They should be 89 50.","Fix them with a hex editor, or: printf '\\x89\\x50' | dd of=status_screen.png bs=1 conv=notrunc"],
  solve:"printf '\\x89\\x50' | dd of=status_screen.png bs=1 count=2 conv=notrunc\nxdg-open status_screen.png   # flag is on the image"
},
{
  id:"s07-openssl-enc", cat:"crypto", tool:"openssl", title:"Sealed Orders", diff:2, points:150,
  files:["secret.enc","note.txt"],
  story:"A file encrypted with OpenSSL (AES-256-CBC, PBKDF2). The passphrase is a weak, aviation-flavoured word that's in the provided wordlist.",
  question:"Brute the passphrase and decrypt the file.",
  tools:[
    {name:"openssl enc", why:"Decrypts the blob once you have the passphrase.", cmd:"openssl enc -d -aes-256-cbc -pbkdf2 -k PASS -in secret.enc"},
    {name:"a bash loop", why:"Try every wordlist entry until one decrypts cleanly.", cmd:"while read p; do openssl enc -d -aes-256-cbc -pbkdf2 -k \"$p\" -in secret.enc 2>/dev/null | grep -qa HOSTBUSTERS && echo $p; done < wordlist"},
    {name:"file header", why:"'Salted__' at the start tells you it's OpenSSL enc with a salt.", cmd:"xxd secret.enc | head -1"}
  ],
  learn:"`openssl enc` files begin with `Salted__` + an 8-byte salt; modern ones derive the key with PBKDF2 (`-pbkdf2`). If the passphrase is weak, loop a wordlist through `openssl enc -d` and keep the password whose output isn't garbage. Note the `-pbkdf2` flag must match how it was encrypted, or every password 'fails'.",
  hints:["xxd secret.enc | head — the 'Salted__' magic confirms OpenSSL enc.","Decrypt with: openssl enc -d -aes-256-cbc -pbkdf2 -k <pass> -in secret.enc","Loop the aviation wordlist; the right password prints readable text (the one here is a turbine-ish word)."],
  solve:"while read p; do openssl enc -d -aes-256-cbc -pbkdf2 -k \"$p\" -in secret.enc 2>/dev/null | grep -qa HOSTBUSTERS && { echo \"pw=$p\"; openssl enc -d -aes-256-cbc -pbkdf2 -k \"$p\" -in secret.enc; break; }; done < ../_shared/aviation_wordlist.txt   # pw: turbine123"
},
{
  id:"s08-john-shadow", cat:"password", tool:"john", title:"Shadow of the Tower", diff:2, points:150,
  files:["shadow","note.txt"],
  story:"A shadow file from the tower workstation. One account has a crackable password; the flag is HOSTBUSTERS{that_password}.",
  question:"Crack the cracker-friendly account and wrap its password as the flag.",
  tools:[
    {name:"john", why:"Auto-detects the $6$ (sha512crypt) format and cracks with a wordlist.", cmd:"john --wordlist=aviation_wordlist.txt shadow"},
    {name:"hashcat", why:"GPU alternative; mode 1800 = sha512crypt.", cmd:"hashcat -m 1800 shadow aviation_wordlist.txt"},
    {name:"unshadow", why:"Combine passwd+shadow when you have both (not needed here).", cmd:"unshadow passwd shadow > hashes"}
  ],
  learn:"`$6$` marks sha512crypt — salted and slow by design, so cracking it needs a good wordlist (brute force is hopeless). `john` fingerprints the format automatically; `john --show` lists what cracked. One account's hash is uncrackable on purpose (don't waste time on root) — picking the right target matters.",
  hints:["john --wordlist=challenges/_shared/aviation_wordlist.txt shadow","Only one account cracks (towerop). root is a dummy — ignore it.","john --show shadow, then wrap the recovered password: HOSTBUSTERS{...} (a contrail-ish word + year)."],
  solve:"john --wordlist=../_shared/aviation_wordlist.txt shadow\njohn --show shadow   # towerop:contrail2026  ->  HOSTBUSTERS{contrail2026}"
},
{
  id:"s09-hashid-crack", cat:"password", tool:"hashid / hashcat", title:"Unknown Hash", diff:2, points:150,
  files:["mystery.hash","note.txt"],
  story:"A single unknown hash dumped from a device. Before you can crack it you have to know what it is.",
  question:"Identify the hash type, crack it, and wrap the password as the flag.",
  tools:[
    {name:"hashid / hash-identifier", why:"Guesses the algorithm (and the hashcat/john mode) from the hash shape.", cmd:"hashid 'da39a3ee...'"},
    {name:"hashcat", why:"Crack once you know the mode (raw-SHA1 = mode 100).", cmd:"hashcat -m 100 mystery.hash aviation_wordlist.txt"},
    {name:"john", why:"Or: john --format=raw-sha1.", cmd:"john --format=raw-sha1 --wordlist=aviation_wordlist.txt mystery.hash"}
  ],
  learn:"Step one is always identification: length and charset narrow it down (40 hex chars → SHA-1 or RIPEMD-160). `hashid` suggests candidates and the matching cracker modes. Pick the most likely, crack with your wordlist, done. Getting the mode wrong is the usual reason 'nothing cracks'.",
  hints:["hashid \"$(cat mystery.hash)\" — 40 hex characters points at SHA-1.","hashcat -m 100 mystery.hash challenges/_shared/aviation_wordlist.txt","Wrap the recovered word as HOSTBUSTERS{...} (an albatross-ish word + a digit)."],
  solve:"hashid \"$(cat mystery.hash)\"\njohn --format=raw-sha1 --wordlist=../_shared/aviation_wordlist.txt mystery.hash\njohn --format=raw-sha1 --show mystery.hash   # albatross7  ->  HOSTBUSTERS{albatross7}"
},
{
  id:"s10-radare2-serial", cat:"reversing", tool:"radare2 / Ghidra", title:"Licence Key", diff:3, points:225,
  files:["licensecheck","note.txt"],
  story:"An avionics licence-key checker. There's no stored key to compare against — it validates your input with arithmetic. Satisfy the maths and it prints the flag.",
  question:"Reverse the validation and craft a key the binary accepts.",
  tools:[
    {name:"radare2 / rizin", why:"Disassemble and read the checks: aaa, then look at the valid() function.", cmd:"r2 -A licensecheck; afl; pdf @ sym.valid"},
    {name:"Ghidra", why:"Decompile valid() to C and read the constraints directly.", cmd:"ghidra (import, analyse, open valid)"},
    {name:"angr (optional)", why:"Symbolic execution can solve the constraints for you.", cmd:"angr: find=print path, avoid=Invalid"}
  ],
  learn:"When a key check has no stored password, it's a constraint problem: the code computes things about your input (length, sum of bytes, XOR, a product of two positions) and compares to constants. Read those constants in the disassembly/decompiler, then build any string that satisfies all of them. The flag is XOR-obfuscated in the binary, so you must actually reach the success path — `strings` won't give it away.",
  hints:["chmod +x licensecheck. In r2: aaa; pdf @ sym.valid — note the length, sum, xor and product checks.","You don't need THE key, just A key satisfying: right length, byte-sum == K1, byte-xor == K2, s[3]*s[7] low byte == K3.","Solve it (by hand or with angr), feed it in, and the success branch de-obfuscates the flag."],
  solve:"# Recover the constants from valid(), then let a solver build a key:\n# e.g. the intended key 'AV26-7X3K-Qp9' satisfies them:\necho 'AV26-7X3K-Qp9' | ./licensecheck"
},
{
  id:"s11-ltrace-strcmp", cat:"reversing", tool:"ltrace", title:"Ramp Auth", diff:2, points:150,
  files:["rampauth","note.txt"],
  story:"A ramp-agent auth binary compares your input to a secret. You could reverse the logic — or just watch the library calls it makes.",
  question:"Recover the password the binary checks, enter it, and read the flag.",
  tools:[
    {name:"ltrace", why:"Traces library calls — and prints the arguments, so strcmp leaks the secret.", cmd:"ltrace ./rampauth"},
    {name:"gdb", why:"Break on strcmp and inspect the arguments if ltrace is unavailable.", cmd:"gdb ./rampauth; b strcmp; run"},
    {name:"strings", why:"Sometimes the secret is just sitting there — always worth a look.", cmd:"strings rampauth"}
  ],
  learn:"Dynamic analysis beats static when a program hands the secret to a library function. `ltrace` logs calls like `strcmp(\"your_input\", \"the_secret\")` — the second argument is the password, no disassembly needed. Type anything at the prompt, read the strcmp in the trace, then run it again with the real value.",
  hints:["chmod +x rampauth. ltrace ./rampauth, then type any guess.","Look at the strcmp() line in the trace — one argument is your guess, the other is the real password.","Run again and enter that password (a zaventem-ramp-ish string) to print the flag."],
  solve:"chmod +x rampauth\nltrace ./rampauth   # type anything; read strcmp(..., \"zaventem-ramp-42\")\necho 'zaventem-ramp-42' | ./rampauth"
},
{
  id:"s12-pdf-stream", cat:"forensics", tool:"pdf-parser", title:"Empty Briefing", diff:3, points:200,
  files:["briefing.pdf","note.txt"],
  story:"A one-page PDF that renders empty. PDFs are containers of objects, and objects can hold compressed streams that never get drawn.",
  question:"Enumerate the PDF's objects, inflate the hidden stream, and read the flag.",
  tools:[
    {name:"pdf-parser.py", why:"Didier Stevens' tool: list objects, dump and decompress streams.", cmd:"pdf-parser.py --stats briefing.pdf; pdf-parser.py -o 5 -f briefing.pdf"},
    {name:"pdfid.py", why:"Quick triage — counts objects, streams, JavaScript, auto-actions.", cmd:"pdfid.py briefing.pdf"},
    {name:"peepdf / mutool", why:"Alternatives for walking and extracting PDF objects.", cmd:"mutool show briefing.pdf 5"}
  ],
  learn:"A PDF is numbered objects; some are `/FlateDecode` streams (zlib-compressed), so `strings` and `binwalk` see nothing useful. `pdfid` triages (how many streams? any JavaScript?), then `pdf-parser.py -o <n> -f` dumps object n with its filters applied — inflating the stream. Malicious PDFs hide payloads exactly this way, so this is a daily blue-team skill too.",
  hints:["pdfid.py briefing.pdf — there's a stream object that the page never references.","pdf-parser.py --stats briefing.pdf to list objects; the interesting one is a FlateDecode stream.","pdf-parser.py -o 5 -f briefing.pdf   (-f applies the filter and inflates it)"],
  solve:"pdfid.py briefing.pdf\npdf-parser.py -o 5 -f briefing.pdf    # the inflated stream holds the flag\n# quick alt: python3 -c \"import re,zlib;d=open('briefing.pdf','rb').read();print([zlib.decompress(m) for m in re.findall(rb'stream\\r?\\n(.*?)\\r?\\nendstream',d,re.S) if m[:2]==b'x\\x9c'])\""
},
{
  id:"s13-cyberchef-magic", cat:"crypto", tool:"CyberChef", title:"Wrapped Intercept", diff:2, points:150,
  files:["intercept.txt","note.txt"],
  story:"A VDL Mode 2 intercept, wrapped in several layers of encoding. No encryption — just an onion of transforms.",
  question:"Peel every layer and recover the plaintext flag.",
  tools:[
    {name:"CyberChef", why:"Drag operations to build the recipe; 'Magic' auto-detects layers.", cmd:"gchq.github.io/CyberChef  →  Magic (with 'Intensive mode')"},
    {name:"CyberChef Magic", why:"Suggests the next decode at each step — great for stacked encodings.", cmd:"Magic operation"},
    {name:"the shell", why:"rev, base64 -d, base32 -d, gunzip, xxd -r -p, and a ROT13 tr do it by hand.", cmd:"rev | base64 -d | ... "}
  ],
  learn:"Layered-encoding puzzles teach you to recognise encodings by shape: Base64 (A–Z/+/=), Base32 (A–Z/2–7), hex (0–9a–f), gzip (starts 1F 8B), reversed strings. CyberChef's 'Magic' detects and suggests each next step; doing it once by hand teaches you what Magic is doing. Order here: reverse → Base64 → Base32 → gunzip → from-hex → ROT13.",
  hints:["The string is reversed first — start with 'Reverse', then look at what you get.","Feed it to CyberChef 'Magic' with Intensive mode and follow the suggestions.","Layers, outermost first: reverse, Base64, Base32, gunzip, from hex, ROT13."],
  solve:"rev intercept.txt | base64 -d | base32 -d | gunzip | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'"
}
];
