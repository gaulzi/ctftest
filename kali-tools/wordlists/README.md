# Aviation password-cracking dictionaries

Built by `generator/make_wordlist.py`. Two files, two jobs:

| File | Lines | What it is |
|---|---|---|
| `aviation-base.txt` | ~800 | Clean base vocabulary, one idea per line — manufacturers, aircraft models, airlines + ICAO codes, airports (ICAO/IATA), cities, ATC phraseology, the phonetic alphabet, engines, icons, and Belgium/Brussels specifics. |
| `aviation-crack.txt` | ~121k | The base list run through realistic password mangling (Capitalized / UPPER / leetspeak, plus year, digit and symbol suffixes). Ready to feed straight to a cracker. |

## Use it

Straight dictionary attack:
```bash
john --wordlist=aviation-crack.txt hashes.txt
hashcat -m 0 hashes.txt aviation-crack.txt          # -m 0 = MD5; pick your mode
```

Better coverage without a giant file — run **rules** over the small base list; the
cracker generates the mutations on the fly:
```bash
hashcat -m 1800 shadow aviation-base.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1800 shadow aviation-base.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
# the big one, if you have it:
hashcat ... aviation-base.txt -r rules/OneRuleToRuleThemAll.rule

john --wordlist=aviation-base.txt --rules=Jumbo hashes.txt
```

Combine with the classics for real targets — aviation words first (fast, targeted),
then fall back to `rockyou.txt`:
```bash
cat aviation-crack.txt /usr/share/wordlists/rockyou.txt > combined.txt
```

## Tuning it

Edit the word groups or the `SUFFIX` / `LEET` lists at the top of
`generator/make_wordlist.py` and re-run `python3 generator/make_wordlist.py`. Add your
own target-specific terms (operator names, tail numbers, staff conventions) at the top —
custom words beat any generic list. `cewl` can also scrape a target's own website into a
wordlist, which pairs well with these.

> For authorised testing and CTF practice only.
