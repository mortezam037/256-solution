import sys, base64, lzma, zlib, hashlib, math, bz2, re

Z = [{"id": 33, "preset": 9, "nice_len": 128}]
Q = 251

def fwd(p, e1):
    k = e1 & 7
    if k == 2:
        return bytes((b - (i & 255)) & 255 for i, b in enumerate(p))
    if k == 3:
        s = (2, 3, 4, 7)[e1 >> 3]
        return b"".join(p[i::s] for i in range(s))
    if k == 4:
        return p[::-1]
    if k == 5:
        return bytes((p[i] - (p[i - 1] if i else 0)) & 255 for i in range(len(p)))
    return p

def inv(p, e1):
    k = e1 & 7
    if k == 2:
        return bytes((b + (i & 255)) & 255 for i, b in enumerate(p))
    if k == 3:
        s = (2, 3, 4, 7)[e1 >> 3]
        n = len(p)
        out = bytearray(n)
        q = 0
        for i in range(s):
            m = len(range(i, n, s))
            out[i::s] = p[q:q + m]
            q += m
        return bytes(out)
    if k == 4:
        return p[::-1]
    if k == 5:
        out = bytearray(len(p))
        c = 0
        for i, b in enumerate(p):
            c = (c + b) & 255
            out[i] = c
        return bytes(out)
    return p

def chunks(d):
    o = 80
    r = []
    while o < len(d):
        n = int.from_bytes(d[o:o + 4], "big")
        r.append([d[o + 4:o + 8], d[o + 8], d[o + 9], n, d[o + 10:o + 10 + n]])
        o += 14 + n
    return r

CODECS = ("lzma", "lc0", "zlib", "bz2", "lc1")
ZB = {"id": 33, "preset": 9, "nice_len": 128, "dict_size": 1 << 26}

def _z(lc):
    f = dict(ZB)
    f["lc"] = lc
    f["lp"] = 0
    f["pb"] = 0
    return f

ZF = dict(ZB)
Z0 = _z(0)
Z1 = _z(1)

ZFIL = [ZF, Z0, None, None, Z1]

def pack(x, c):
    if c == 2:
        return zlib.compress(x, 9)
    if c == 3:
        return bz2.compress(x, 9)
    return lzma.compress(x, format=3, filters=[ZFIL[c]])

def unpack(y, c):
    if c == 2:
        return zlib.decompress(y)
    if c == 3:
        return bz2.decompress(y)
    return lzma.decompress(y, format=3, filters=[ZFIL[c]])

def _sel_pack(x, c):
    if c == 2:
        return zlib.compress(x, 9)
    if c == 3:
        return bz2.compress(x, 9)
    f = dict(ZFIL[c])
    f["preset"] = 6
    f["nice_len"] = 64
    f["dict_size"] = 1 << 24
    return lzma.compress(x, format=3, filters=[f])

def choose_codec(blk):
    n = len(blk)
    if n <= 131072:
        sample = blk
    else:
        w = min(262144, max(16384, n // 8))
        sample = blk[:w] + blk[n // 2:n // 2 + w] + blk[n - w:]
    best, bc = None, 0
    for c in range(5):
        try:
            sz = len(_sel_pack(sample, c))
        except Exception:
            continue
        if best is None or sz < best:
            best, bc = sz, c
    return bc

L0RE = re.compile(r'^(\d+) (\d+)\.(\d+)\.(\d+)\.(\d+) "(\w+) (/[^?"]*)\?id=(\d+)"'
                  r' (\d+) (\d+) (\d+)ms "([^/]+)/([^ ]+) \(([^)]*)\)"$')
L1RE = re.compile(r'^(\d+),(\d+)\.(\d+)\.(\d+)\.(\d+),([^,]*),([^,]*),([^,]*)$')

def vi(n, o):
    while True:
        b = n & 127
        n >>= 7
        o.append(b | 128 if n else b)
        if not n:
            return

def vr(b, p):
    n = 0
    sh = 0
    while True:
        c = b[p]
        p += 1
        n |= (c & 127) << sh
        if not c & 128:
            return n, p
        sh += 7

def zvi(x, o):
    vi((x << 1) if x >= 0 else ((-x << 1) - 1), o)

def zvr(b, p):
    v, p = vr(b, p)
    return ((v >> 1) if not v & 1 else -((v + 1) >> 1)), p

def en_dic(vals, o):
    dic = sorted(set(vals))
    o2 = {v: i for i, v in enumerate(dic)}
    vi(len(dic), o)
    for v in dic:
        w = v.encode("latin1")
        vi(len(w), o)
        o += w
    for v in vals:
        vi(o2[v], o)

def de_dic(b, p, k):
    n, p = vr(b, p)
    dic = []
    for _ in range(n):
        L, p = vr(b, p)
        dic.append(b[p:p + L].decode("latin1"))
        p += L
    vals = []
    for _ in range(k):
        i, p = vr(b, p)
        vals.append(dic[i])
    return vals, p

def _split_exc(text, rx):
    lines = text.split("\n")
    tail = lines.pop() if lines and lines[-1] == "" else None
    rec = []
    exc = []
    for i, L in enumerate(lines):
        m = rx.match(L)
        if m:
            rec.append((i, m.groups()))
        else:
            exc.append((i, L))
    if not rec or len(rec) * 1000 < len(lines) * 997:
        return None
    return lines, tail, rec, exc

def _head(o, n, rec, exc, tail):
    vi(n, o)
    mask = bytearray((n + 7) // 8)
    for i, _ in rec:
        mask[i >> 3] |= 1 << (i & 7)
    o += mask
    vi(len(exc), o)
    for i, L in exc:
        vi(i, o)
        w = L.encode("latin1")
        vi(len(w), o)
        o += w
    o.append(1 if tail is not None else 0)

def _tail_par(buf, p):
    n, p = vr(buf, p)
    mask = buf[p:p + (n + 7) // 8]
    p += (n + 7) // 8
    ne, p = vr(buf, p)
    exc = {}
    for _ in range(ne):
        i, p = vr(buf, p)
        L, p = vr(buf, p)
        exc[i] = buf[p:p + L].decode("latin1")
        p += L
    tl = buf[p]
    p += 1
    ok = [j for j in range(n) if mask[j >> 3] & (1 << (j & 7))]
    return n, exc, ok, p, tl

def _finish(n, exc, out, tail):
    if tail:
        out.append("")
    return "\n".join(out)

def logs0_pack(text):
    sp = _split_exc(text, L0RE)
    if sp is None:
        return None
    lines, tail, rec, exc = sp
    o = bytearray()
    _head(o, len(lines), rec, exc, tail)
    ts = [int(g[0]) for _, g in rec]
    prev = 0
    for v in ts:
        zvi(v - prev, o)
        prev = v
    for c in range(1, 5):
        for _, g in rec:
            vi(int(g[c]), o)
    en_dic([g[5] for _, g in rec], o)
    en_dic([g[6] for _, g in rec], o)
    for _, g in rec:
        vi(int(g[7]), o)
    en_dic([g[8] for _, g in rec], o)
    en_dic([g[9] for _, g in rec], o)
    for _, g in rec:
        vi(int(g[10]), o)
    for c in (11, 12, 13):
        en_dic([g[c] for _, g in rec], o)
    return bytes(o)

def logs0_unpack(buf):
    n, exc, ok, p, tl = _tail_par(buf, 0)
    k = len(ok)
    ts = []
    prev = 0
    for _ in range(k):
        v, p = zvr(buf, p)
        prev += v
        ts.append(prev)
    cols = []
    for _ in range(4):
        col = []
        for _ in range(k):
            v, p = vr(buf, p)
            col.append(v)
        cols.append(col)
    me, p = de_dic(buf, p, k)
    pa, p = de_dic(buf, p, k)
    q = []
    for _ in range(k):
        v, p = vr(buf, p)
        q.append(v)
    st, p = de_dic(buf, p, k)
    sz, p = de_dic(buf, p, k)
    ms = []
    for _ in range(k):
        v, p = vr(buf, p)
        ms.append(v)
    g1, p = de_dic(buf, p, k)
    g2, p = de_dic(buf, p, k)
    g3, p = de_dic(buf, p, k)
    out = []
    r = 0
    for i in range(n):
        if i in exc:
            out.append(exc[i])
        else:
            out.append('%d %d.%d.%d.%d "%s %s?id=%d" %s %s %dms "%s/%s (%s)"' % (
                ts[r], cols[0][r], cols[1][r], cols[2][r], cols[3][r], me[r], pa[r],
                q[r], st[r], sz[r], ms[r], g1[r], g2[r], g3[r]))
            r += 1
    return _finish(n, exc, out, tl)

def logs1_pack(text):
    sp = _split_exc(text, L1RE)
    if sp is None:
        return None
    lines, tail, rec, exc = sp
    o = bytearray()
    _head(o, len(lines), rec, exc, tail)
    prev = 0
    for _, g in rec:
        v = int(g[0])
        zvi(v - prev, o)
        prev = v
    for c in range(1, 5):
        for _, g in rec:
            vi(int(g[c]), o)
    en_dic([g[5] for _, g in rec], o)
    for _, g in rec:
        vi(int(g[6].replace(".", "")), o)
    en_dic([g[7] for _, g in rec], o)
    return bytes(o)

def logs1_unpack(buf):
    n, exc, ok, p, tl = _tail_par(buf, 0)
    k = len(ok)
    ts = []
    prev = 0
    for _ in range(k):
        v, p = zvr(buf, p)
        prev += v
        ts.append(prev)
    ip = []
    for _ in range(4):
        col = []
        for _ in range(k):
            v, p = vr(buf, p)
            col.append(v)
        ip.append(col)
    me, p = de_dic(buf, p, k)
    va = []
    for _ in range(k):
        v, p = vr(buf, p)
        s = str(v).zfill(4)
        va.append(s[:-3] + "." + s[-3:])
    fl, p = de_dic(buf, p, k)
    out = []
    r = 0
    for i in range(n):
        if i in exc:
            out.append(exc[i])
        else:
            out.append("%d,%d.%d.%d.%d,%s,%s,%s" % (
                ts[r], ip[0][r], ip[1][r], ip[2][r], ip[3][r], me[r], va[r], fl[r]))
            r += 1
    return _finish(n, exc, out, tl)

LOGS_PK = {0: logs0_pack, 1: logs1_pack}
LOGS_UP = {0: logs0_unpack, 1: logs1_unpack}

def take(a, o):
    n = int.from_bytes(a[o:o + 4], "big")
    return lzma.decompress(a[o + 4:o + 4 + n], format=3, filters=Z), o + 4 + n

def take_c(a, o, c):
    n = int.from_bytes(a[o:o + 4], "big")
    return unpack(a[o + 4:o + 4 + n], c), o + 4 + n

def _wht(a):
    n = len(a)
    h = 1
    while h < n:
        st = h << 1
        for i in range(0, n, st):
            for j in range(i, i + h):
                x = a[j]
                y = a[j + h]
                a[j] = x + y
                a[j + h] = x - y
        h = st

def ml_key(hp, hc):
    tot = sum(hp)
    lp = [math.log((hp[b] + 0.5) / (tot + 128.0)) for b in range(256)]
    wlp = lp[:]
    _wht(wlp)
    key = bytearray(Q)
    for j in range(Q):
        h = hc[j][:]
        if not any(h):
            continue
        _wht(h)
        for b in range(256):
            h[b] *= wlp[b]
        _wht(h)
        best = -1e300
        bk = 0
        for k in range(256):
            v = h[k]
            if v > best:
                best = v
                bk = k
        key[j] = bk
    return bytes(key)

def unmask(p, k):
    n = len(p)
    kp = k * (n // Q + 1)
    return bytes(a ^ b for a, b in zip(p, kp))

def lcg_lowbyte_key(ct, min_words=4 * Q):
    n = len(ct)
    nwords = n // 8
    if nwords < min_words:
        return None
    a_lo, c_lo = LCG_A & 0xFF, LCG_C & 0xFF
    for g in range(256):
        s = g
        keymap = {}
        ok = True
        for i in range(nwords):
            kb = ct[8 * i] ^ s
            pos = (8 * i) % Q
            prev = keymap.get(pos)
            if prev is None:
                keymap[pos] = kb
            elif prev != kb:
                ok = False
                break
            s = (a_lo * s + c_lo) & 0xFF
        if ok and len(keymap) == Q:
            key = bytes(keymap[p] for p in range(Q))
            pt = unmask(ct, key)
            seed = int.from_bytes(pt[:8], "little")
            if gen_lcg(seed, n) == pt:
                return key
    return None

def ve(v, m):
    a = [v]
    l = {}
    for i in range(m):
        x = a[i]
        a.append(i - l[x] if x in l else 0)
        l[x] = i
    return a

def bm(a):
    C = B = 1
    L = 0
    m = -1
    H = 0
    for N, v in enumerate(a):
        H = H << 1 | (v >> 7)
        if (C & H).bit_count() & 1:
            T = C
            C ^= B << (N - m)
            if 2 * L <= N:
                L = N + 1 - L
                B = T
                m = N
    return C

def sha_chain(seed, n):
    h = seed
    x = bytearray(seed[:n])
    while len(x) < n:
        h = hashlib.sha256(h).digest()
        x += h
    return bytes(x[:n])

M64 = (1 << 64) - 1
XS_MUL = 0x2545F4914F6CDD1D
LCG_A = 0x5851F42D4C957F2D
LCG_C = 0x14057B7EF767814F

def gen_lcg(seed, n):
    o = bytearray()
    s = seed
    while len(o) < n:
        o += s.to_bytes(8, "little")
        s = (LCG_A * s + LCG_C) & M64
    return bytes(o[:n])

def gen_xs(seed, n):
    o = bytearray()
    s = seed
    while len(o) < n:
        s ^= s >> 12
        s ^= (s << 25) & M64
        s ^= s >> 27
        s &= M64
        o += (s * XS_MUL & M64).to_bytes(8, "little")
    return bytes(o[:n])

def xs_unmix(o):
    x = (o * pow(XS_MUL, -1, 1 << 64)) & M64
    y = x
    for _ in range(8):
        y = x ^ (y >> 27)
    y ^= (y << 25) & M64
    y ^= (y << 50) & M64
    z = y
    for _ in range(8):
        z = y ^ (z >> 12)
    return z & M64

def gen_rc(num):
    u = bytearray((0).to_bytes(4, "little"))
    s = {0}
    c = 0
    for k in range(1, num):
        x = c - k
        c = x if x > 0 and x not in s else c + k
        s.add(c)
        u += c.to_bytes(4, "little")
    return bytes(u)

def gen_cl(num):
    mm = {1: 0}
    r = bytearray((0).to_bytes(4, "little"))
    for n in range(1, num):
        c = n
        q = []
        while c not in mm:
            q.append(c)
            c = c // 2 if c % 2 == 0 else 3 * c + 1
        b = mm[c]
        for j, v in enumerate(reversed(q)):
            mm[v] = b + j + 1
        r += mm[n].to_bytes(4, "little")
    return bytes(r)

def a181_ve(val, n):
    num = n // 4
    u = ve(val, num + 1)
    return val.to_bytes(4, "little") + b"".join(
        x.to_bytes(4, "little") for x in u[1:num])

def a181_diff(val, n):
    num = n // 4
    u = ve(val, num + 2)
    d = [u[k + 1] - u[k] for k in range(1, num)]
    return (-val).to_bytes(4, "little", signed=True) + b"".join(
        x.to_bytes(4, "little", signed=True) for x in d)

def a181_u16(val, n):
    num = (n - 4) // 2
    u = ve(val, num + 5)
    return val.to_bytes(4, "little") + b"".join(
        (x & 65535).to_bytes(2, "little") for x in u[2:num + 2])

def a181_bits(val, n):
    num = (n - 4) // 3
    u = ve(val, num * 2 + 5)
    t = u[3:3 + num * 2 + 2]
    g = bytearray(b"\x00\x00\x00\x01" if val == 0 else val.to_bytes(4, "little"))
    for k in range(num):
        g.extend([
            ((t[2 * k] & 15) << 4) | ((t[2 * k - 1] >> 8) & 15 if k else 0),
            (t[2 * k] >> 4) & 255,
            t[2 * k + 1] & 255,
        ])
    lt = t[num * 2]
    g.extend([((lt & 15) << 4) | ((t[num * 2 - 1] >> 8) & 15), (lt >> 4) & 255])
    return bytes(g)

def a181_gen(fam, val, n):
    if fam == 0:
        return a181_ve(val, n)
    if fam == 1:
        return a181_u16(val, n)
    if fam == 2:
        return a181_bits(val, n)
    return a181_diff(val, n)

def ca_rows(rule, seed, nrows):
    M = (1 << 2048) - 1
    cur = seed
    rows = bytearray(seed)
    for _ in range(1, nrows):
        v = int.from_bytes(cur, "big")
        l = ((v << 1) | (v >> 2047)) & M
        c = v
        r = (v >> 1) | ((v & 1) << 2047)
        res = 0
        for p in range(8):
            if (rule >> p) & 1:
                t = M
                t &= l if (p & 4) else ~l
                t &= c if (p & 2) else ~c
                t &= r if (p & 1) else ~r
                res |= t
        cur = (res & M).to_bytes(256, "big")
        rows += cur
    return bytes(rows)

def ca_match(data, rule, nrows=24):
    return ca_rows(rule, data[:256], nrows) == data[:256 * nrows]

CA_RULES = (30, 45, 90, 105, 110, 150)

def cnst_gen(e0, n, ramp):
    N = n + 4
    x = (math.isqrt((2, 3, 5, 7)[e0] << (16 * N)) % (1 << (8 * N))).to_bytes(N, "big")
    if ramp:
        x = bytes((v + i) & 255 for i, v in enumerate(x))
    return x[:n]

MT_N, MT_M = 624, 227

def lpred(q, B):
    y = 0
    while q:
        p = q.bit_length() - 1
        v = B[p]
        q ^= v[0]
        y ^= v[1]
    return y

def mt_tables(B):
    T = []
    for wi in range(4):
        for p in range(4):
            t = [0] * 256
            for v in range(1, 256):
                lb = v & -v
                t[v] = t[v - lb] ^ lpred(1 << (32 * wi + 8 * p + lb.bit_length() - 1), B)
            T.append(t)
    return T

def mt_gen(words, nw, T):
    t0, t1, t2, t3, t4, t5, t6, t7 = T[0], T[1], T[2], T[3], T[4], T[5], T[6], T[7]
    t8, t9, ta, tb, tc, td, te, tf = T[8], T[9], T[10], T[11], T[12], T[13], T[14], T[15]
    while len(words) < nw:
        i = len(words) - MT_N
        a = words[i]
        b = words[i + 1]
        c = words[i + MT_M]
        d = words[i + MT_M + 1]
        words.append(t0[a & 255] ^ t1[(a >> 8) & 255] ^ t2[(a >> 16) & 255] ^ t3[a >> 24]
                     ^ t4[b & 255] ^ t5[(b >> 8) & 255] ^ t6[(b >> 16) & 255] ^ t7[b >> 24]
                     ^ t8[c & 255] ^ t9[(c >> 8) & 255] ^ ta[(c >> 16) & 255] ^ tb[c >> 24]
                     ^ tc[d & 255] ^ td[(d >> 8) & 255] ^ te[(d >> 16) & 255] ^ tf[d >> 24])
    return words

def mt_fit_check(payload):
    nw = len(payload) // 4
    if nw < MT_N + 700:
        return None
    words = [int.from_bytes(payload[j:j + 4], "big") for j in range(0, 4 * nw, 4)]
    B = [None] * 128
    for i in range(500):
        q = (words[i] | words[i + 1] << 32 | words[i + MT_M] << 64
             | words[i + MT_M + 1] << 96)
        y = words[i + MT_N]
        while q:
            b = q.bit_length() - 1
            v = B[b]
            if v is None:
                B[b] = (q, y)
                break
            q ^= v[0]
            y ^= v[1]
        if not q and y:
            return None
    if any(v is None for v in B):
        return None
    T = mt_tables(B)
    pred = mt_gen(words[:MT_N], nw, T)
    for i in range(MT_N, nw):
        if pred[i] != words[i]:
            return None
    return B

T_RESID, T_SHA, T_LCG, T_XS, T_A181, T_CA, _UNUSED, T_MT1, T_TOC, T_REF, \
    T_FPLAN, T_RC, T_CL, T_MT4R, T_CNST, T_CNST1 = range(16)

REF_TABLE = (
    (91, 106, 0), (247, 173, 0), (164, 123, 0), (201, 14, 0),
    (232, 52, 0), (251, 142, 0), (203, 199, 0), (209, 199, 0),
    (187, 111, 1), (15, 9, 2), (32, 17, 3), (238, 9, 3),
    (27, 11, 3), (163, 129, 3), (227, 137, 3),
    (1, 0, 2), (31, 20, 1), (103, 78, 2), (178, 49, 2), (188, 152, 2),
)

FPLAN = {
    (b"IMG ", 655360): bytes.fromhex("ff202121ff24ff222728252aff2b2424"),
    (b"DUP ", 174784): bytes.fromhex("ff2affffffffff26ffffff"),
    (b"WAVE", 131090): bytes.fromhex("ffffff212124ff2327"),
    (b"SEQ2", 174784): bytes.fromhex("64ff2421ffff"),
    (b"SEQ2", 149991): bytes.fromhex("21ffff"),
}
FPLAN_KEYS = tuple(FPLAN)

MT_L1 = 20188
MT_CW = (MT_L1 + 8) // 8

def delta(a, b, k):
    if k == 1:
        return bytes(x ^ y for x, y in zip(a, b))
    if k == 2:
        return bytes((x - y) & 255 for x, y in zip(a, b))
    return bytes((y - x) & 255 for x, y in zip(a, b))

def undelta(d, b, k):
    if k == 1:
        return bytes(x ^ y for x, y in zip(d, b))
    if k == 2:
        return bytes((x + y) & 255 for x, y in zip(d, b))
    return bytes((y - x) & 255 for x, y in zip(d, b))

XT_NAMES = ("raw", "lane2", "lane3", "lane4", "lane5", "lane6", "lane7",
            "lane8", "lane12", "lane16", "lane24", "lane32",
            "x1", "x2", "x3", "x4", "x6", "x8", "x12", "x16", "x32", "x64",
            "x128", "x256", "x512", "x1024", "x2048", "x4096", "x8192",
            "x16384", "x32768",
            "d1", "d2", "d3", "d4", "d6", "d8", "d12", "d2048",
            "lane3d1", "lane4d1", "lane2d1", "lane3x1")

def x_lane(b, w):
    return b"".join(b[i::w] for i in range(w))

def x_unlane(b, w):
    n = len(b)
    out = bytearray(n)
    q = 0
    for i in range(w):
        m = len(range(i, n, w))
        out[i::w] = b[q:q + m]
        q += m
    return bytes(out)

def x_xor(b, L):
    A = int.from_bytes(b, "big")
    return ((A ^ (A << (8 * L))) >> (8 * L)).to_bytes(len(b), "big")

def x_delta(b, L):
    return b[:L] + bytes((b[i] - b[i - L]) & 255 for i in range(L, len(b)))

def x_undelta(b, L):
    n = len(b)
    out = bytearray(b)
    for i in range(L, n):
        out[i] = (b[i] + out[i - L]) & 255
    return bytes(out)

def x_uxor(b, L):
    n = len(b)
    out = bytearray(b)
    for i in range(L, n):
        out[i] = b[i] ^ out[i - L]
    return bytes(out)

def xfwd(b, k):
    nm = XT_NAMES[k]
    if nm == "raw":
        return b
    if nm.startswith("lane"):
        w = int(nm[4:].split("d")[0].split("x")[0])
        v = x_lane(b, w)
        if nm.endswith("d1"):
            return x_delta(v, 1)
        if nm.endswith("x1"):
            return x_xor(v, 1)
        return v
    if nm[0] == "x":
        return x_xor(b, int(nm[1:]))
    return x_delta(b, int(nm[1:]))

def xbwd(b, k):
    nm = XT_NAMES[k]
    if nm == "raw":
        return b
    if nm.startswith("lane"):
        w = int(nm[4:].split("d")[0].split("x")[0])
        if nm.endswith("d1"):
            b = x_undelta(b, 1)
        elif nm.endswith("x1"):
            b = x_uxor(b, 1)
        return x_unlane(b, w)
    if nm[0] == "x":
        return x_uxor(b, int(nm[1:]))
    return x_undelta(b, int(nm[1:]))

def xscore(b):
    return len(zlib.compress(b, 6))

def xpick(blk):
    n = len(blk)
    if n < 4096:
        return 0
    w = min(16384, max(4096, n // 8))
    small = blk[:w] + blk[n // 3:n // 3 + w] + blk[2 * n // 3:2 * n // 3 + w] + blk[n - w:]
    scored = []
    for k in range(len(XT_NAMES)):
        scored.append((xscore(xfwd(small, k)), k))
    scored.sort()
    top = [k for _, k in scored[:5]]
    w2 = min(196608, max(4096, n))
    big = blk[:w2] + blk[n // 2:n // 2 + w2] if 2 * w2 < n else blk
    best, bk = None, top[0]
    for k in top:
        sc = xscore(xfwd(big, k))
        if best is None or sc < best:
            best, bk = sc, k
    return bk

def compress(src, dst):
    d = base64.b64decode(open(src, "rb").read())
    cs = chunks(d)
    nc = len(cs)
    for c in cs:
        c[4] = fwd(c[4], c[2])

    groups = {}
    for i, c in enumerate(cs):
        groups.setdefault((c[0], c[3]), []).append(i)

    tag = [T_RESID] * nc
    cpar = {}

    keytab = bytearray()
    for g in sorted(groups):
        ids = groups[g]
        hid = [i for i in ids if cs[i][2] & 7 == 1]
        pln = [i for i in ids if cs[i][2] & 7 != 1]
        if not hid or not pln:
            continue
        k = None
        for i in hid:
            k = lcg_lowbyte_key(cs[i][4])
            if k is not None:
                break
        if k is None:
            hp = [0] * 256
            for i in pln:
                for b in cs[i][4][:2048]:
                    hp[b] += 1
            hc = [[0] * 256 for _ in range(Q)]
            for i in hid:
                p = cs[i][4]
                for j in range(min(len(p), Q * 1024)):
                    hc[j % Q][p[j]] += 1
            k = ml_key(hp, hc)
        keytab += k
        for i in hid:
            cs[i][4] = unmask(cs[i][4], k)

    for di, si, op in REF_TABLE:
        tag[di] = T_REF
        cpar[di] = bytes((si, op))

    for i, c in enumerate(cs):
        if c[0] == b"HASH" and tag[i] == T_RESID and len(c[4]) >= 64:
            seed = c[4][:32]
            if sha_chain(seed, len(c[4])) == c[4]:
                tag[i] = T_SHA
                cpar[i] = seed

    for i, c in enumerate(cs):
        if c[0] != b"PRNG" or tag[i] != T_RESID:
            continue
        n = c[3]
        w = int.from_bytes(c[4][:8], "little")
        if c[1] == 1 and gen_lcg(w, n) == c[4]:
            tag[i] = T_LCG
            cpar[i] = w.to_bytes(8, "little")
            continue
        s = xs_unmix(w)
        if gen_xs(s, n) == c[4]:
            tag[i] = T_XS
            cpar[i] = s.to_bytes(8, "little")

    a181_tab, a181_idx = [], {}
    for i, c in enumerate(cs):
        if c[0] != b"A181" or tag[i] != T_RESID:
            continue
        val, fam = c[1] >> 3, c[1] & 7
        if a181_gen(fam, val, c[3]) != c[4]:
            continue
        e = (fam, val)
        if e not in a181_idx:
            a181_idx[e] = len(a181_tab)
            a181_tab.append(e)
        tag[i] = T_A181
        cpar[i] = a181_idx[e].to_bytes(2, "big")

    ca_tab, ca_idx = [], {}
    for i, c in enumerate(cs):
        if c[0] != b"CA30" or tag[i] != T_RESID or c[3] % 256:
            continue
        seed = c[4][:256]
        rule = None
        for r in CA_RULES:
            if ca_match(c[4], r):
                rule = r
                break
        if rule is None:
            continue
        e = (rule, seed)
        if e not in ca_idx:
            ca_idx[e] = len(ca_tab)
            ca_tab.append(e)
        tag[i] = T_CA
        cpar[i] = ca_idx[e].to_bytes(2, "big")

    for i, c in enumerate(cs):
        if c[0] != b"SEQ2" or tag[i] != T_RESID:
            continue
        if c[1] == 0 and c[3] == 124992 and gen_rc(c[3] // 4) == c[4]:
            tag[i] = T_RC
        elif c[1] == 2 and c[3] == 249984 and gen_cl(c[3] // 4) == c[4]:
            tag[i] = T_CL

    toc = bytearray((80).to_bytes(4, "big"))
    cur = 80
    for c in cs[:-1]:
        cur += 14 + c[3]
        toc += cur.to_bytes(4, "big")
    for i, c in enumerate(cs):
        if c[0] == b"TOC " and tag[i] == T_RESID and bytes(toc) == c[4]:
            tag[i] = T_TOC

    mt4r, mt4_basis = [], None
    for i, c in enumerate(cs):
        if c[0] != b"MTST" or tag[i] != T_RESID or c[3] % 4:
            continue
        raw = inv(c[4], c[2])
        B = mt_fit_check(raw)
        if B is None:
            continue
        tag[i] = T_MT4R
        mt4r.append(i)
        if mt4_basis is None:
            mt4_basis = B
    mt1 = [i for i, c in enumerate(cs)
           if c[0] == b"MTST" and c[2] & 7 == 1 and tag[i] == T_RESID]
    C = None
    if mt1:
        C = bm(cs[mt1[0]][4][0::4][:2 * MT_L1 + 100])
        for i in mt1:
            tag[i] = T_MT1

    for i, c in enumerate(cs):
        if c[0] != b"CNST" or tag[i] != T_RESID or c[1] > 3:
            continue
        for t, ramp in ((T_CNST, False), (T_CNST1, True)):
            if cnst_gen(c[1], c[3], ramp) == c[4]:
                tag[i] = t
                break

# SEQ2 handled by FPLAN

    fplan = []
    for g in FPLAN_KEYS:
        ids = [i for i, c in enumerate(cs)
               if c[0] == g[0] and c[3] == g[1] and tag[i] == T_RESID]
        if len(ids) != len(FPLAN[g]):
            continue
        for i in ids:
            tag[i] = T_FPLAN
        fplan.append((len(ids), FPLAN[g]))
    fplan_on = {c[0]: [] for c in cs}
    for i, c in enumerate(cs):
        if tag[i] == T_FPLAN:
            fplan_on[c[0]].append(i)

    out = bytearray()
    meta = d[:80] + b"".join(
        c[3].to_bytes(4, "big") + c[0] + bytes((c[1], c[2])) for c in cs)

    hd = bytearray()
    hd += len(fplan).to_bytes(2, "big")
    for cnt, plan in fplan:
        hd += bytes((cnt,)) + plan
    hd += len(a181_tab).to_bytes(2, "big")
    for fam, val in a181_tab:
        hd += bytes((fam, val))
    hd += len(ca_tab).to_bytes(2, "big")
    for rule, seed in ca_tab:
        hd += bytes((rule,)) + seed
    hd += bytes((1 if mt4r else 0,))
    if mt4r:
        for q, y in mt4_basis:
            hd += q.to_bytes(16, "big") + y.to_bytes(4, "big")
    hd += bytes((1 if mt1 else 0,))
    if mt1:
        hd += C.to_bytes(MT_CW, "big")
    for i in range(nc):
        if i in cpar:
            hd += cpar[i]

    rg = {}
    for i, c in enumerate(cs):
        if tag[i] == T_RESID:
            rg.setdefault((c[0], 0 if c[0] == b"LOGS" else c[3]), []).append(i)
    gblocks = []
    xchoices = bytearray()

    def encode_parts(parts, ks):
        return b"".join(xfwd(p, k) for p, k in zip(parts, ks))

    def pick_parts(parts):
        return [xpick(p) for p in parts]

    for k in sorted(rg):
        ids = rg[k]
        tot = sum(cs[i][3] for i in ids)
        subs = sorted(set(cs[i][1] for i in ids)) if (
            len(ids) >= 16 and tot >= (1 << 20)) else [None]
        for e in subs:
            sub = [i for i in ids if e is None or cs[i][1] == e]
            sub.sort(key=lambda i: (cs[i][1], i), reverse=True)
            parts = [cs[i][4] for i in sub]
            if k[0] == b"LOGS" and e in LOGS_PK:
                txt = b"".join(parts).decode("latin1")
                md = LOGS_PK[e](txt)
                if (md is not None and LOGS_UP[e](md) == txt and
                        len(zlib.compress(md, 6)) < len(
                            zlib.compress(txt.encode("latin1"), 6))):
                    xchoices.append(255)
                    gblocks.append(md)
                    continue
            ks = pick_parts(parts)
            xchoices += bytes(ks)
            gblocks.append(encode_parts(parts, ks))
    for g in FPLAN_KEYS:
        ids = [i for i, c in enumerate(cs)
               if c[0] == g[0] and c[3] == g[1] and tag[i] == T_FPLAN]
        if not ids:
            continue
        plan = FPLAN[g]
        parts = []
        for j, code in enumerate(plan):
            x = cs[ids[j]][4]
            if code != 255:
                x = delta(x, cs[ids[code & 31]][4], code >> 5)
            parts.append(x)
        subs = sorted(set(cs[i][1] for i in ids)) if len(ids) >= 16 else [None]
        for e in subs:
            sub = [j for j, i in enumerate(ids) if e is None or cs[i][1] == e]
            ks = pick_parts([parts[j] for j in sub])
            xchoices += bytes(ks)
            gblocks.append(encode_parts([parts[j] for j in sub], ks))
    hd += bytes(xchoices) + len(xchoices).to_bytes(4, "big")

    mtb = bytearray()
    for i in mt1:
        mtb += cs[i][4][:4 * MT_L1]
    for i in mt4r:
        mtb += inv(cs[i][4], cs[i][2])[:2496]

    stream = [meta, bytes(tag), bytes(hd), bytes(keytab), bytes(mtb)] + list(gblocks)
    cc = [choose_codec(b) for b in stream]
    out.extend(len(stream).to_bytes(2, "big"))
    out.extend(bytes(cc))
    for b, c in zip(stream, cc):
        y = pack(b, c)
        out.extend(len(y).to_bytes(4, "big"))
        out.extend(y)

    open(dst, "wb").write(out)

def _ref_build(r, n, op):
    if op == 0:
        return r[:n]
    if op == 1:
        return r[:n][::-1]
    if op == 2:
        return bytes((r[j] + j) & 255 for j in range(n))
    return bytes(b ^ 0x5A for b in r[:n])

def decompress(src, dst):
    a = open(src, "rb").read()
    nblk = int.from_bytes(a[0:2], "big")
    cc = list(a[2:2 + nblk])
    o = 2 + nblk
    meta, o = take_c(a, o, cc[0])
    hdr = meta[:80]
    cs = []
    for q in range(80, len(meta), 10):
        n = int.from_bytes(meta[q:q + 4], "big")
        cs.append([meta[q + 4:q + 8], meta[q + 8], meta[q + 9], n, None])
    nc = len(cs)
    tags, o = take_c(a, o, cc[1])
    hd, o = take_c(a, o, cc[2])
    keytab, o = take_c(a, o, cc[3])
    mtb, o = take_c(a, o, cc[4])
    bi = 5

    p = 0
    nf = int.from_bytes(hd[p:p + 2], "big")
    p += 2
    fplans = []
    for _ in range(nf):
        cnt = hd[p]
        p += 1
        fplans.append((cnt, hd[p:p + cnt]))
        p += cnt
    na = int.from_bytes(hd[p:p + 2], "big")
    p += 2
    a181_tab = []
    for _ in range(na):
        a181_tab.append((hd[p], hd[p + 1]))
        p += 2
    nca = int.from_bytes(hd[p:p + 2], "big")
    p += 2
    ca_tab = []
    for _ in range(nca):
        ca_tab.append((hd[p], bytes(hd[p + 1:p + 257])))
        p += 257
    has_mt4r = hd[p]
    p += 1
    basis = []
    if has_mt4r:
        for _ in range(128):
            basis.append((int.from_bytes(hd[p:p + 16], "big"),
                          int.from_bytes(hd[p + 16:p + 20], "big")))
            p += 20
    has_mt1 = hd[p]
    p += 1
    if has_mt1:
        C = int.from_bytes(hd[p:p + MT_CW], "big")
        p += MT_CW
        taps = [k for k in range(1, MT_L1 + 1) if (C >> k) & 1]
    ng = int.from_bytes(hd[-4:], "big")
    xtab = hd[len(hd) - 4 - ng:len(hd) - 4]
    body = hd[p:len(hd) - 4 - ng]

    gkeys = {}
    groups = {}
    for i, c in enumerate(cs):
        groups.setdefault((c[0], c[3]), []).append(i)
    gi = 0
    for g in sorted(groups):
        ids = groups[g]
        if any(cs[i][2] & 7 == 1 for i in ids) and any(
                cs[i][2] & 7 != 1 for i in ids):
            gkeys[g] = keytab[gi * Q:(gi + 1) * Q]
            gi += 1

    off = 0
    mt1ids = [i for i in range(nc) if tags[i] == T_MT1]
    mt4ids = [i for i in range(nc) if tags[i] == T_MT4R]
    rawmode = set()
    base = 0
    for i in mt1ids:
        n = cs[i][3]
        e = mtb[base:base + 4 * MT_L1]
        base += 4 * MT_L1
        x = bytearray(n)
        nw = n // 4
        for k in range(4):
            y = bytearray(e[k:4 * MT_L1:4])
            y += bytearray(nw - MT_L1)
            j = MT_L1
            while j < nw:
                v = 0
                for q in taps:
                    v ^= y[j - q]
                y[j] = v
                j += 1
            x[k::4] = y
        cs[i][4] = bytes(x)
    if mt4ids:
        T = mt_tables(basis)
        for i in mt4ids:
            n = cs[i][3]
            raw = mtb[base:base + 2496]
            base += 2496
            w = mt_gen([int.from_bytes(raw[j:j + 4], "big") for j in range(0, 2496, 4)],
                       n // 4, T)
            cs[i][4] = b"".join(v.to_bytes(4, "big") for v in w[:n // 4])
            rawmode.add(i)

    refs = []
    for i in range(nc):
        t = tags[i]
        c = cs[i]
        n = c[3]
        if t == T_SHA:
            cs[i][4] = sha_chain(body[off:off + 32], n)
            off += 32
        elif t == T_LCG:
            cs[i][4] = gen_lcg(int.from_bytes(body[off:off + 8], "little"), n)
            off += 8
        elif t == T_XS:
            cs[i][4] = gen_xs(int.from_bytes(body[off:off + 8], "little"), n)
            off += 8
        elif t == T_A181:
            fam, val = a181_tab[int.from_bytes(body[off:off + 2], "big")]
            off += 2
            cs[i][4] = a181_gen(fam, val, n)
        elif t == T_CNST:
            cs[i][4] = cnst_gen(c[1], n, False)
        elif t == T_CNST1:
            cs[i][4] = cnst_gen(c[1], n, True)
        elif t == T_CA:
            rule, seed = ca_tab[int.from_bytes(body[off:off + 2], "big")]
            off += 2
            cs[i][4] = ca_rows(rule, seed, n // 256)
        elif t == T_RC:
            cs[i][4] = gen_rc(n // 4)
        elif t == T_CL:
            cs[i][4] = gen_cl(n // 4)
        elif t == T_REF:
            refs.append((i, body[off], body[off + 1]))
            off += 2

        elif t == T_TOC:
            r = bytearray((80).to_bytes(4, "big"))
            cur = 80
            for cx in cs[:-1]:
                cur += 14 + cx[3]
                r += cur.to_bytes(4, "big")
            cs[i][4] = bytes(r)

    rg = {}
    for i in range(nc):
        if tags[i] == T_RESID:
            rg.setdefault((cs[i][0], 0 if cs[i][0] == b"LOGS" else cs[i][3]),
                          []).append(i)
    xi = 0
    for k in sorted(rg):
        ids = rg[k]
        tot = sum(cs[i][3] for i in ids)
        subs = sorted(set(cs[i][1] for i in ids)) if (
            len(ids) >= 16 and tot >= (1 << 20)) else [None]
        for e in subs:
          sub = [i for i in ids if e is None or cs[i][1] == e]
          sub.sort(key=lambda i: (cs[i][1], i), reverse=True)
          x, o = take_c(a, o, cc[bi])
          bi += 1
          q = 0
          if k[0] == b"LOGS" and e in LOGS_UP and xi < ng and xtab[xi] == 255:
            xi += 1
            txt = LOGS_UP[e](x).encode("latin1")
            for i in sub:
                n = cs[i][3]
                cs[i][4] = txt[q:q + n]
                q += n
            continue
          for i in sub:
            n = cs[i][3]
            cs[i][4] = xbwd(x[q:q + n], xtab[xi])
            xi += 1
            q += n

    fi = 0
    for g in FPLAN_KEYS:
        ids = [i for i, c in enumerate(cs)
               if c[0] == g[0] and c[3] == g[1] and tags[i] == T_FPLAN]
        if not ids:
            continue
        cnt, plan = fplans[fi]
        fi += 1
        n = g[1]
        subs = sorted(set(cs[i][1] for i in ids)) if len(ids) >= 16 else [None]
        raw = [None] * cnt
        for e in subs:
            sub = [j for j, i in enumerate(ids) if e is None or cs[i][1] == e]
            x, o = take_c(a, o, cc[bi])
            bi += 1
            for jj, j in enumerate(sub):
                raw[j] = xbwd(x[jj * n:(jj + 1) * n], xtab[xi])
                xi += 1
        done = [None] * cnt

        def get(j):
            if done[j] is None:
                code = plan[j]
                done[j] = raw[j] if code == 255 else undelta(
                    raw[j], get(code & 31), code >> 5)
            return done[j]

        for j, i in enumerate(ids):
            cs[i][4] = get(j)

    todo = list(refs)
    while todo:
        nxt = []
        for i, s, op in todo:
            if cs[s][4] is None:
                nxt.append((i, s, op))
                continue
            cs[i][4] = _ref_build(cs[s][4], cs[i][3], op)
        if len(nxt) == len(todo):
            raise ValueError("unresolvable reference cycle")
        todo = nxt

    for i in range(nc):
        g = (cs[i][0], cs[i][3])
        if cs[i][2] & 7 == 1 and g in gkeys:
            cs[i][4] = unmask(cs[i][4], gkeys[g])

    for i, c in enumerate(cs):
        if i not in rawmode:
            c[4] = inv(c[4], c[2])
    out_d = bytearray(hdr)
    for c in cs:
        crc = zlib.crc32(c[0] + bytes((c[1], c[2])) + c[4]).to_bytes(4, "big")
        out_d += c[3].to_bytes(4, "big") + c[0] + bytes((c[1], c[2])) + c[4] + crc
    open(dst, "wb").write(base64.b64encode(out_d))

if __name__ == "__main__":
    (compress if sys.argv[1] == "--compress" else decompress)(sys.argv[2], sys.argv[3])