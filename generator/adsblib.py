"""Minimal ADS-B (Mode S DF17 extended squitter) encoder for training data."""

CHARSET = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"
GENERATOR = 0x1FFF409


def crc24(bits_int: int, nbits: int) -> int:
    """Mode S CRC: remainder of (msg << 24) / generator."""
    data = bits_int << 24
    total = nbits + 24
    for i in range(total - 1, 23, -1):
        if data & (1 << i):
            data ^= GENERATOR << (i - 24)
    return data & 0xFFFFFF


def df17(icao: int, me: int, ca: int = 5, corrupt=False) -> str:
    head = (17 << 3) | ca
    body = (head << 80) | (icao << 56) | me          # 88 bits
    pi = crc24(body, 88)
    if corrupt:
        pi ^= 0x00A5A5
    return "%028X" % ((body << 24) | pi)


def ident_me(callsign: str, tc: int = 4, cat: int = 3) -> int:
    cs = callsign.upper().ljust(8)[:8]
    me = (tc << 3) | cat
    for ch in cs:
        idx = CHARSET.index(ch) if ch != "#" else 0
        me = (me << 6) | idx
    return me


def velocity_me(v_ew: int, v_ns: int, vrate_fpm: int = 0) -> int:
    """Subtype 1 airborne velocity. v_ew > 0 = east, v_ns > 0 = north (knots)."""
    bits = []

    def put(val, n):
        bits.append((val, n))

    put(19, 5)          # TC
    put(1, 3)           # subtype 1 (ground speed, subsonic)
    put(0, 1)           # intent change
    put(0, 1)           # IFR capability
    put(1, 3)           # NACv
    put(1 if v_ew < 0 else 0, 1)
    put(abs(v_ew) + 1, 10)
    put(1 if v_ns < 0 else 0, 1)
    put(abs(v_ns) + 1, 10)
    put(1, 1)           # vertical rate source: baro
    put(1 if vrate_fpm < 0 else 0, 1)
    put(abs(vrate_fpm) // 64 + 1, 9)
    put(0, 2)           # reserved
    put(0, 1)           # GNSS/baro diff sign
    put(0, 7)           # diff
    me = 0
    for v, n in bits:
        me = (me << n) | (v & ((1 << n) - 1))
    return me
