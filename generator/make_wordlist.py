#!/usr/bin/env python3
"""Build an aviation-themed password-cracking dictionary.

    python3 generator/make_wordlist.py

Produces:
  kali-tools/wordlists/aviation-base.txt   - unique base vocabulary (one idea per line)
  kali-tools/wordlists/aviation-crack.txt  - base + realistic mangling, deduped

Use with:  john --wordlist=aviation-crack.txt hashes
           hashcat -m <mode> hashes aviation-base.txt -r /usr/share/hashcat/rules/best64.rule
"""
import os, itertools

OUT = os.path.join(os.path.dirname(__file__), "..", "kali-tools", "wordlists")
os.makedirs(OUT, exist_ok=True)

# ----------------------------------------------------------------- base vocab
MANUFACTURERS = """boeing airbus embraer bombardier cessna piper gulfstream dassault lockheed
northrop fokker antonov tupolev sukhoi ilyushin mitsubishi atr beechcraft cirrus diamond
pilatus hondajet saab bae mcdonnell douglas convair learjet grumman cessna textron daher
sikorsky bell robinson agusta leonardo irkut comac tecnam socata extra pipistrel""".split()

MODELS = """737 747 757 767 777 787 707 727 717 737max a220 a300 a310 a318 a319 a320 a321
a330 a340 a350 a380 a321neo a320neo e170 e175 e190 e195 e2 crj700 crj900 crj1000 dash8 dhc6
dhc8 atr42 atr72 md80 md11 md90 dc3 dc6 dc8 dc9 dc10 l1011 concorde c130 c17 c5 kc135 c172
c152 c182 c206 c208 pa28 pa38 pa44 sr20 sr22 da40 da42 pc12 pc24 king200 king350 tbm930
spitfire mustang hurricane lancaster mosquito hercules globemaster galaxy raptor hornet
superhornet lightning viper falcon tomcat eagle strikeeagle warthog thunderbolt blackbird
nighthawk f14 f15 f16 f18 f22 f35 sr71 u2 b1 b2 b52 a10 av8 harrier typhoon rafale gripen
mig29 su27 su35""".split()

AIRLINES = """delta united american lufthansa emirates qatar ryanair easyjet british klm
airfrance brussels sas iberia alitalia qantas singapore cathay ana jal turkish etihad
southwest jetblue alaska virgin wizz vueling tap swiss austrian finnair norwegian aerlingus
sabena luxair condor eurowings transavia pegasus sunexpress aegean icelandair westjet
spirit frontier hawaiian airindia indigo cebu lion garuda thai korean asiana china eva
latam avianca gol azul copa aeromexico ethiopian kenya egypt royaljordanian saudia oman
gulfair kuwait flydubai airbaltic tarom lot croatia airserbia bulgaria""".split()

AIRLINE_ICAO = """dal ual aal dlh uae qtr ryr ezy baw klm afr bel sas ibe aza qfa sia cpa
ana jal thy etd swa jbu asa vir wzz vlg tap swr aua fin nax ein lux clx ewg tra pgt aee ice
wja nks fft hal aic igo ceb lni gia tha kal aar csn evA tam avA glo azu cmp amx eth kqa msr
rja sva oma gfa kac fdb bti rot acl asl""".split()

AIRPORTS_ICAO = """ebbr egll ehAm lfpg eddf eddm eddl edds kjfk klax ksfo kord katl kden
kdfw kiah kmia kbos ksea klas kphx komd omdb wsss rjtt rjaa vhhh yssy ymml ltba ltfm lemd
lebl lirf limc lszh lszb ekch engm essa efhk lppt loww eidw egkk egcc eglc egss lfpo lfmn
lgav lgts lkpr lhbp epwa eplL lrop uuee ulli zbaa zspd zgsz rksi romt vabb vidp vtbs wmkk
wiii rpll fajs hecA otbd oerk oejn omaa""".split()

AIRPORTS_IATA = """bru lhr ams cdg fra muc dus str jfk lax sfo ord atl den dfw iah mia bos
sea las phx dxb sin hnd nrt hkg syd mel ist saw mad bcn fco mxp zrh gva cph osl arn hel lis
vie dub lgw man lcy stn ory nce ath skg prg bud waw krk gva otp svo led pek pvg szx icn
bom del bkk kul cgk mnl jnb cai doh ruh jed auh""".split()

CITIES = """brussels zaventem charleroi antwerp liege ostend london heathrow gatwick stansted
luton paris orly roissy amsterdam schiphol frankfurt munich dusseldorf newyork losangeles
chicago atlanta dallas denver miami boston seattle vegas phoenix dubai singapore tokyo
hongkong sydney melbourne istanbul madrid barcelona rome milan zurich geneva copenhagen
oslo stockholm helsinki lisbon vienna dublin manchester prague budapest warsaw moscow
beijing shanghai seoul mumbai delhi bangkok kualalumpur jakarta manila johannesburg cairo
doha riyadh jeddah""".split()

TERMS = """runway taxiway apron tarmac ramp hangar cockpit flightdeck fuselage wing aileron
elevator rudder flaps slats spoiler throttle yoke sidestick trim gear landinggear nosegear
altimeter airspeed altitude heading bearing vector transponder squawk ident autopilot
autothrottle autoland flightlevel heading approach departure arrival takeoff landing
touchdown flare rotate climb descent cruise holding stack final base downwind crosswind
upwind headwind tailwind goaround missed clearance pushback taxi gate stand jetway jetbridge
deicing anti_ice turnaround boarding deplane cabin galley lavatory overhead jumpseat
flightcrew captain firstofficer copilot purser dispatcher loadmaster marshaller controller
tower ground approach center radar beacon ils vor dme ndb rnav rnp waypoint fix airway
jetstream contrail slipstream stall spin bank pitch roll yaw thrust lift drag payload ballast
ceiling visibility gusts windshear turbulence icing fog overcast scattered broken cavok
mayday panpan roger wilco affirm negative standby cleared monitor flightplan metar taf notam
atis qnh qfe transition squawk7500 squawk7600 squawk7700 vfr ifr crosscheck checklist
v1 vr v2 vref vne redline blueline feather windmill reverser spoilers airbrake flaperon""".split()

PHONETIC = """alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike
november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu""".split()

ENGINES = """cfm cfm56 leap v2500 pw1100 pw4000 jt8d jt9d cf6 genx trent trent900 trent1000
rb211 pw geared turbofan turbojet turboprop ramjet afterburner apu pratt whitney rollsroyce
generalelectric""".split()

ICONS = """concorde sprucegoose airforceone redarrows blueangels thunderbirds topgun maverick
goose iceman rooster wright lindbergh earhart yeager redbaron ace aces aviator pilot
aviation flying airplane aeroplane jet jetliner airliner widebody narrowbody turboprop
biplane glider chopper helicopter chopper skyhawk skywagon warbird dogfight scramble
afterburner machone mach2 supersonic hypersonic cleared4takeoff fullthrottle wheelsup""".split()

BELGIUM = """belgium belgian skeyes belgocontrol eurocontrol brusselsairlines sabena sn
brusselsairport zaventem charleroi liegeairport antwerpairport ostendairport ebbr bru
oosna oosta tomorrowland atomium manneken grandplace waffle""".split()

# words that must survive so the CTF's own crack challenges still work
CHALLENGE = """turbine contrail albatross cockpit landinggear skyhawk jetstream boeing airbus
cessna password admin welcome""".split()

def norm(w):
    return "".join(ch for ch in w.lower() if ch.isalnum() or ch == "_").strip("_")

base = []
seen = set()
for group in (MANUFACTURERS, MODELS, AIRLINES, AIRLINE_ICAO, AIRPORTS_ICAO, AIRPORTS_IATA,
              CITIES, TERMS, PHONETIC, ENGINES, ICONS, BELGIUM, CHALLENGE):
    for w in group:
        n = norm(w)
        if n and n not in seen:
            seen.add(n)
            base.append(n)

# a few high-signal compounds people actually use as passwords
for a, b in [("boeing", "747"), ("boeing", "737"), ("airbus", "320"), ("airbus", "380"),
             ("cessna", "172"), ("piper", "cub"), ("red", "baron"), ("top", "gun"),
             ("sky", "hawk"), ("jet", "stream"), ("after", "burner"), ("mach", "one"),
             ("brussels", "airlines"), ("air", "force")]:
    n = a + b
    if n not in seen:
        seen.add(n); base.append(n)

with open(os.path.join(OUT, "aviation-base.txt"), "w") as f:
    f.write("\n".join(base) + "\n")

# ----------------------------------------------------------------- mangling
# curated suffixes: years, common tails, aviation numbers
SUFFIX = ["", "1", "2", "3", "7", "12", "123", "1234", "01", "11", "69", "99", "007", "420",
          "!", "!!", "@", "#", "$", "1!", "123!", "2020", "2021", "2022", "2023", "2024",
          "2025", "2026", "2k24", "2k25", "2k26", "172", "737", "747", "320", "380", "911",
          "1903", "1969", "2000"]

LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

def leet(w):
    return "".join(LEET.get(c, c) for c in w)

def cap(w):
    return w[:1].upper() + w[1:]

out = []
emit = set()
def add(x):
    if x not in emit and 3 <= len(x) <= 24:
        emit.add(x); out.append(x)

for w in base:
    forms = [w, cap(w), w.upper()]
    l = leet(w)
    if l != w:
        forms.append(l)
    for stem in forms:
        for suf in SUFFIX:
            add(stem + suf)

# keep a sensible order: shorter/plainer first (crackers try early lines first)
out.sort(key=lambda s: (len(s), s))
with open(os.path.join(OUT, "aviation-crack.txt"), "w") as f:
    f.write("\n".join(out) + "\n")

print("base words:", len(base))
print("cracking list:", len(out), "entries")
print("files in", os.path.abspath(OUT))
