# -*- coding: utf-8 -*-
"""捷成公文 .ods 批次解碼工具（獨立版，不需 ODSVIEW / Frida）

用法：
  python ods_batch.py 資料夾 [輸出資料夾]
  python ods_batch.py 檔案1.ods 檔案2.ods ...

輸出：
  - 每個 .ods 產生同名 .txt（UTF-8）
  - 正文依版面重排：每行 38 字元、首行 4 空格縮排（與原系統 .txt 匯出一致）
  - 保留文件內的空格
"""
import io, sys, os, struct, glob, time
try:
    for _s in (sys.stdout, sys.stderr):
        if _s is not None and hasattr(_s, 'reconfigure'):
            _s.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ---------------------------- LFSR ----------------------------
class LFSR:
    def __init__(self, seed):
        self.s0 = seed & 0xFFFF
        self.s1 = (seed >> 16) & 0xFFFF
        if self.s0 == 0: self.s0 = 1
        if self.s1 == 0: self.s1 = 1
    def next16(self):
        new0 = ((self.s0 << 1) | ((self.s0 >> 15) & 1)) & 0xFFFF
        bit0 = (self.s0 & 1) ^ (new0 & 1)
        self.s0 = (new0 & 0xFFFE) | bit0
        new1 = ((self.s1 >> 1) | ((self.s1 << 15) & 0xFFFF)) & 0xFFFF
        bit14 = (self.s1 & 0x4000) ^ ((new1 >> 1) & 0x4000)
        self.s1 = (new1 & 0xBFFF) | bit14
        return (self.s0 ^ self.s1) & 0xFFFF

def s8(b):
    return b if b < 0x80 else b - 0x100

# ---------------------------- 解碼 ----------------------------
def find_record_areas(data):
    """找所有記錄區：2-byte 數量 + 00 00 + 字記錄（型態1=35B / 型態0=21B）"""
    n = len(data)
    for off in range(0x100, n - 30):
        cnt = struct.unpack('<H', data[off:off+2])[0]
        if not (1 <= cnt <= 500) or data[off+2:off+4] != b'\x00\x00':
            continue
        base = off + 4
        p = base
        ok = True
        for _ in range(min(3, cnt)):
            if p + 15 > n:      # 要讀 data[p+14]，需 p+14 < n
                ok = False
                break
            typ = data[p+14]
            rlen = 35 if typ != 0 else 21
            if p + rlen > n:
                ok = False
                break
            ctr = struct.unpack('<H', data[p+10:p+12])[0]
            if ctr == 0 or ctr > 0x1000:
                ok = False
                break
            p += rlen
        if ok:
            yield off, cnt

def decode_at(data, base, cnt):
    out = []
    count = 0x050A6440 + 0x200D8 + cnt   # 樣板貢獻 + 邊界常數 + 字數
    k = 0
    p = base
    while k < cnt:
        r = data[p:p+35]
        if len(r) < 21:
            break
        typ = r[14]
        rlen = 35 if typ != 0 else 21
        if p + rlen > len(data):
            break
        r = data[p:p+rlen]
        byte0, byte1, byte2 = r[0], r[1], r[2]
        w33 = struct.unpack('<H', r[3:5])[0] & 0xFF
        w34 = struct.unpack('<H', r[5:7])[0] & 0xFF
        w35 = struct.unpack('<H', r[7:9])[0] & 0xFF
        b31 = r[9]
        di = struct.unpack('<H', r[10:12])[0]
        ebp8 = struct.unpack('<H', r[12:14])[0]
        X = struct.unpack('<H', r[15:17])[0]
        if typ != 0:
            byte2d, byte2e, byte2f = r[17], r[18], r[19]
            byte26, byte27 = r[20], r[21]
            d28 = struct.unpack('<I', r[22:26])[0]
            coord1 = struct.unpack('<H', r[26:28])[0]
            coord2 = struct.unpack('<H', r[28:30])[0]
            byte0c = r[30]
            w0e = struct.unpack('<H', r[31:33])[0]
            w10 = struct.unpack('<H', r[33:35])[0]
        else:
            byte2d = byte2e = byte2f = 0
            byte26 = byte27 = 0
            d28 = 0xFFFFFF
            coord1 = struct.unpack('<H', r[17:19])[0]
            coord2 = struct.unpack('<H', r[19:21])[0]
            byte0c = 0x64
            w0e = w10 = 0
        chk = (byte1 + byte0 + b31 + s8(byte2) + s8(w33) + s8(w34) + s8(w35) + di + ebp8 - 1) & 0xFFFF
        count = (count + chk) & 0xFFFFFFFF
        key = LFSR(count).next16()
        code = X ^ key
        sum16 = (byte2d + code + byte2e + byte2f + coord1 + coord2 + byte0c + w0e + w10) & 0xFFFF
        count = (count + sum16 + d28 + byte26 + byte27) & 0xFFFFFFFF
        out.append(code)
        k += 1
        p += rlen
    return out

STATUS_FAST = 'fast'        # 已知樣板常數直接解出
STATUS_CACHE = 'cache'      # 批次種子快取命中
STATUS_AUTO = 'auto'        # 自動反推 count0
STATUS_NOT_JASON = 'not_jason'  # 不是捷成公文格式（可能是 ODF 試算表/壓縮檔）
STATUS_UNKNOWN = 'unknown'  # 捷成格式但解不出（未知變體或檔案損壞）


def decode_status(data, cache=None, allow_full_sweep=False):
    """回傳 (codes, status)。解不出時 codes=None。"""
    if not data.startswith(b'JASON\x00'):
        return None, STATUS_NOT_JASON
    # 快速路徑：已知樣板常數（3簽－便簽A4）
    best = None
    for off, cnt in find_record_areas(data):
        try:
            codes = decode_at(data, off + 4, cnt)
            valid = sum(1 for c in codes if big5(c) != '\ufffd')
            ratio = valid / max(1, len(codes))
            if ratio > 0.8 and (best is None or len(codes) > best[0]):
                best = (len(codes), ratio, codes)
        except Exception:
            continue
    if best is not None and best[1] > 0.92 and len(best[2]) >= 20:
        return best[2], STATUS_FAST
    # 自動反推 count0
    try:
        codes = auto_decode(data, cache=cache, allow_full_sweep=allow_full_sweep)
        if codes:
            return codes, STATUS_AUTO
    except Exception:
        pass
    return None, STATUS_UNKNOWN


def decode(data):
    """回傳 codes；解不出時拋 ValueError。"""
    codes, status = decode_status(data)
    if codes is None:
        raise ValueError('無法解碼（' + ('非捷成格式' if status == STATUS_NOT_JASON else '未知變體或檔案損壞') + '）')
    return codes


# ---------------------------- 自動 count0 反推（2004 年代格式） ----------------------------

def _s8(b):
    return b if b < 0x80 else b - 0x100

def _find_areas(data, mincnt=8):
    n = len(data)
    areas = []
    for off in range(0x100, n - 30):
        cnt = struct.unpack('<H', data[off:off+2])[0]
        # 上限原為 2000，但實測有本文區達 2053-2570 筆（「簽」類長公文），會被整個排除；
        # 放寬後仍有結構驗證（型態、ctr、座標、區長度不得超出檔案）把關。
        if not (mincnt <= cnt <= 20000) or data[off+2:off+4] != b'\x00\x00':
            continue
        p = off + 4
        ok = True
        for _ in range(min(4, cnt)):
            if p + 35 > n:
                ok = False
                break
            typ = data[p+14]
            if typ not in (0, 1):
                ok = False
                break
            rlen = 35 if typ != 0 else 21
            if p + rlen > n:
                ok = False
                break
            ctr = struct.unpack('<H', data[p+10:p+12])[0]
            if not (0 < ctr <= 0x4000):
                ok = False
                break
            if rlen == 35:
                c1 = struct.unpack('<H', data[p+26:p+28])[0]
                c2 = struct.unpack('<H', data[p+28:p+30])[0]
            else:
                c1 = struct.unpack('<H', data[p+17:p+19])[0]
                c2 = struct.unpack('<H', data[p+19:p+21])[0]
            if c1 > 1000 or not (5 < c2 < 500):
                ok = False
                break
            p += rlen
        # 區長度要逐筆走完才準：型態0 只有 21 bytes，若一律以 35 估算，
        # 位在檔尾、型態0 居多的本文區會被誤判超出檔案而整區漏掉（26 份真變體即此因）。
        if ok and _area_end(data, off, cnt) is not None:
            areas.append((off, cnt))
    return areas

def _area_end(data, off, cnt):
    """逐筆走完記錄區，回傳區尾位移；超出檔案則回傳 None。"""
    n = len(data)
    p = off + 4
    for _ in range(cnt):
        if p + 15 > n:
            return None
        p += 35 if data[p+14] != 0 else 21
        if p > n:
            return None
    return p

def _parse_recs(data, base, cnt):
    n = len(data)
    recs = []
    p = base
    for _ in range(cnt):
        r = data[p:p+35]
        if len(r) < 21 or p + 35 > n:
            break
        typ = r[14]
        rlen = 35 if typ != 0 else 21
        if p + rlen > n:
            break
        r = data[p:p+rlen]
        byte0, byte1, byte2 = r[0], r[1], r[2]
        w33 = struct.unpack('<H', r[3:5])[0] & 0xFF
        w34 = struct.unpack('<H', r[5:7])[0] & 0xFF
        w35 = struct.unpack('<H', r[7:9])[0] & 0xFF
        b31 = r[9]
        di = struct.unpack('<H', r[10:12])[0]
        ebp8 = struct.unpack('<H', r[12:14])[0]
        X = struct.unpack('<H', r[15:17])[0]
        if typ != 0:
            byte2d, byte2e, byte2f = r[17], r[18], r[19]
            byte26, byte27 = r[20], r[21]
            d28 = struct.unpack('<I', r[22:26])[0]
            coord1 = struct.unpack('<H', r[26:28])[0]
            coord2 = struct.unpack('<H', r[28:30])[0]
            byte0c = r[30]
            w0e = struct.unpack('<H', r[31:33])[0]
            w10 = struct.unpack('<H', r[33:35])[0]
        else:
            byte2d = byte2e = byte2f = 0
            byte26 = byte27 = 0
            d28 = 0xFFFFFF
            coord1 = struct.unpack('<H', r[17:19])[0]
            coord2 = struct.unpack('<H', r[19:21])[0]
            byte0c = 0x64
            w0e = w10 = 0
        recs.append((X, byte0, byte1, byte2, w33, w34, w35, b31, di, ebp8, typ,
                     byte2d, byte2e, byte2f, byte26, byte27, d28, coord1, coord2, byte0c, w0e, w10))
        p += rlen
    return recs

def _lfsr_next16v(counts):
    s0 = counts & 0xFFFF
    s1 = (counts >> 16) & 0xFFFF
    s0 = np.where(s0 == 0, 1, s0)
    s1 = np.where(s1 == 0, 1, s1)
    new0 = ((s0 << 1) | (s0 >> 15)) & 0xFFFF
    bit0 = (s0 & 1) ^ (new0 & 1)
    s0n = (new0 & 0xFFFE) | bit0
    new1 = ((s1 >> 1) | ((s1 << 15) & 0xFFFF)) & 0xFFFF
    bit14 = (s1 & 0x4000) ^ ((new1 >> 1) & 0x4000)
    s1n = (new1 & 0xBFFF) | bit14
    return (s0n ^ s1n) & 0xFFFF

def _valid_big5(codes):
    hi = (codes >> 8) & 0xFF
    lo = codes & 0xFF
    big5ok = (hi >= 0xA1) & (hi <= 0xF9) & (((lo >= 0x40) & (lo <= 0x7E)) | ((lo >= 0xA1) & (lo <= 0xFE)))
    asc = (codes >= 0x20) & (codes < 0x7F)
    sp = (codes == 0) | (codes == 0x0D) | (codes == 0x0A)
    return big5ok | asc | sp

def _build_tables():
    g = np.zeros(65536, dtype=np.int64)
    h_inv = [[] for _ in range(65536)]
    for s in range(65536):
        ss = s if s != 0 else 1
        new0 = ((ss << 1) | (ss >> 15)) & 0xFFFF
        bit0 = (ss & 1) ^ (new0 & 1)
        g[s] = (new0 & 0xFFFE) | bit0
        s1in = s if s != 0 else 1
        new1 = ((s1in >> 1) | ((s1in << 15) & 0xFFFF)) & 0xFFFF
        bit14 = (s1in & 0x4000) ^ ((new1 >> 1) & 0x4000)
        ns1 = (new1 & 0xBFFF) | bit14
        h_inv[ns1].append(s)
    s1a = np.full(65536, -1, dtype=np.int64)
    s1b = np.full(65536, -1, dtype=np.int64)
    s1c = np.full(65536, -1, dtype=np.int64)
    for out, pre in enumerate(h_inv):
        if pre:
            s1a[out] = pre[0]
        if len(pre) > 1:
            s1b[out] = pre[1]
        if len(pre) > 2:
            s1c[out] = pre[2]
    return g, s1a, s1b, s1c

_G, _S1A, _S1B, _S1C = None, None, None, None
_S0ARR = None

def _ensure_tables():
    global _G, _S1A, _S1B, _S1C, _S0ARR, np
    if 'np' not in globals():
        import numpy as np
    if _G is None:
        _G, _S1A, _S1B, _S1C = _build_tables()
        _S0ARR = np.arange(65536, dtype=np.int64)

_STARTERS = [
    0xA140, 0xA544, 0xA440, 0xA5BB, 0xA147, 0xC3F6, 0xA9D3, 0xAC64,
    0xAB65, 0xA8CC, 0xA95E, 0xC2D4, 0xB771, 0xB466, 0xA65D, 0xAED7,
    0xA6B3, 0xB651, 0xB676, 0xACE3, 0xAFF7, 0xB3AF, 0xB45F, 0xBBA1,
    0xACB0, 0xC5B3, 0xC0C0, 0xB867, 0xBEDA, 0xADE3, 0xBFED, 0xB4A9,
    0xACA2, 0xA8E7, 0xA4E5, 0xB07C, 0xB3A1, 0xB77C, 0xB870, 0xB342,
    0xA7BD, 0xA9D2, 0xAED5, 0xC2E0, 0xA5D3, 0xB3F8, 0xBDD0, 0xAED6,
    0xA84D, 0xC4B3, 0xBC66, 0xBFEC, 0xB27A, 0xB14E, 0xA477, 0xA5BC,
    0xAB44, 0xA4A3, 0xB54C, 0xA655, 0xB8D3, 0xA8E4, 0xA6B9, 0xB27B,
    0xA5BF, 0xB0C6, 0xA965, 0xADFB, 0xAAF8, 0xA978, 0xA5C1, 0xB0EA,
    0xA67E, 0xA4EB, 0xA4E9, 0xA578, 0xB941, 0xBAAE, 0xAA4C, 0xA4F4,
    0xB1D0, 0xBDC3, 0xAAC0, 0xB05D, 0xA5E6, 0xB3D2, 0xAA6B, 0xA4BA,
    0xA57E, 0xA4A4, 0xAF53, 0xB14D, 0xA4BD, 0xA870, 0xA457, 0xA455,
    0xADEC, 0xA6B8, 0xB2C4, 0xA641, 0xA8C3, 0xA542, 0xBB50, 0xA4CE,
    0xA9CE, 0xA759, 0xAD59, 0xA670, 0xA548, 0xA9F3, 0xA5D1, 0xB171,
    0xA656, 0xB9EF, 0xB44E, 0xA7C6, 0xACDF, 0xC2D0, 0xA5DC, 0xA8FC,
    0xAABE, 0xB178, 0xB7D3, 0xA8A3, 0xA569, 0xB16F, 0xC0B3, 0xB6B7,
    0xAFE0, 0xA8AC, 0xAC4F, 0xA75F, 0xAB68, 0xABE1, 0xB5A5, 0xA4A7,
    0xA4B4, 0xB3CC, 0xB8FB, 0xA7F3, 0xBBE1, 0xACC6, 0xB7A5, 0xA5FE,
    0xA4C0, 0xB6B5, 0xB4DA, 0xA5D8, 0xB860, 0xB3B9, 0xB1F8,
    # 2026-08-02 由 _sweep_variants.py 全字碼窮舉找出（見 交接Codex-變體破解.md）。
    # 這些「第一個字」多半是本文區前的非文字記錄，解出來是罕用字，但整條 count 鏈正確。
    0xC5F1, 0xC5EE, 0xC3F5,          # 囑/鷥/鏨：2012-2015 計畫、意見類（最常見，IDX=0）
    0xA764, 0xA763, 0xA973,          # 吳/呃/孟：電子信箱答復類
    0xB16F,                          # 得
    0xA15D, 0x0020,                  # （、半形空白：較通用的字元，只放一般清單不放優先清單
    0xADD7,                          # 修：「修正「…辦法」部分條文」法規稿（2026-10-17 窮舉，IDX=15）
]

# 優先起始字（常見本文開頭，依頻率排序）
_STARTERS_PRIORITY = [0xA544, 0xA440, 0xA140, 0xA5BB, 0xA9D3, 0xAC64, 0xAB65, 0xA8CC,
                      0xC3F6, 0xA147, 0xAC4F, 0xA6B3, 0xB651, 0xB676, 0xB771, 0xB466,
                      0xA95E, 0xAED7, 0xACE3, 0xAFF7, 0xB3AF, 0xB45F, 0xBBA1, 0xC0C0,
                      # 窮舉找出且為罕用字（誤判風險低）者放進優先清單，可掃全 IDX 範圍
                      0xC5F1, 0xC5EE, 0xC3F5, 0xA764, 0xA763, 0xA973, 0xB16F]
_STARTERS_REST = [s for s in _STARTERS if s not in set(_STARTERS_PRIORITY)]

def _scan_starter_all(data, recs, starter, idx_max=130, nfilter=10, cache_idxs=None, idx_known=None):
    """對單一起始字掃描：回傳通過前 nfilter 字過濾的 [(seed0, IDX)]"""
    _ensure_tables()
    X0 = recs[0][0]
    r0 = recs[0]
    chk0 = (r0[2] + r0[1] + r0[7] + _s8(r0[3]) + _s8(r0[4]) + _s8(r0[5]) + _s8(r0[6]) + r0[8] + r0[9] - 1) & 0xFFFF
    results = []
    key0 = X0 ^ starter
    target = (key0 ^ _G) & 0xFFFF
    for s1v in (_S1A, _S1B, _S1C):
        s1_by_s0 = s1v[target]
        seed = ((s1_by_s0 << 16) | _S0ARR) & 0xFFFFFFFF
        count0 = (seed - np.uint32(chk0)) & 0xFFFFFFFF
        hi = (count0 >> 24) & 0xFF
        if cache_idxs:
            idx_arr = np.array(cache_idxs, dtype=np.int64)
            cand = np.nonzero((s1_by_s0 >= 0) & np.isin(hi, idx_arr))[0]
        elif idx_known:
            idx_arr = np.array(idx_known, dtype=np.int64)
            cand = np.nonzero((s1_by_s0 >= 0) & np.isin(hi, idx_arr))[0]
        else:
            cand = np.nonzero((s1_by_s0 >= 0) & (hi <= idx_max))[0]
        if len(cand) == 0:
            continue
        co = count0[cand].astype(np.uint32)
        mask = np.ones(len(co), dtype=bool)
        for r in recs[:nfilter]:
            (X, byte0, byte1, byte2, w33, w34, w35, b31, di, ebp8, typ,
             byte2d, byte2e, byte2f, byte26, byte27, d28, coord1, coord2, byte0c, w0e, w10) = r
            chk = (byte1 + byte0 + b31 + _s8(byte2) + _s8(w33) + _s8(w34) + _s8(w35) + di + ebp8 - 1) & 0xFFFF
            co = (co + np.uint32(chk)) & 0xFFFFFFFF
            key = _lfsr_next16v(co)
            code = (X ^ key) & 0xFFFF
            mask &= _valid_big5(code)
            sum16 = (byte2d + code + byte2e + byte2f + coord1 + coord2 + byte0c + w0e + w10) & 0xFFFF
            co = (co + np.uint32(sum16) + np.uint32(d28) + np.uint32(byte26) + np.uint32(byte27)) & 0xFFFFFFFF
            if not mask.any():
                break
        surv = np.nonzero(mask)[0]
        for j in surv:
            results.append((int(count0[cand[j]]), int(hi[cand[j]])))
    return results

def _full_sweep_count0(data, recs, idxs=(0, 5, 10, 40, 85), nfilter=12):
    """不依賴起始字：對指定 IDX 全集掃 checksum（2^24）"""
    _ensure_tables()
    results = []
    cs = np.arange(1 << 24, dtype=np.uint32)
    for IDX in idxs:
        orig = (np.uint32(IDX << 24) | cs)
        co = orig
        for r in recs[:nfilter]:
            (X, byte0, byte1, byte2, w33, w34, w35, b31, di, ebp8, typ,
             byte2d, byte2e, byte2f, byte26, byte27, d28, coord1, coord2, byte0c, w0e, w10) = r
            chk = (byte1 + byte0 + b31 + _s8(byte2) + _s8(w33) + _s8(w34) + _s8(w35) + di + ebp8 - 1) & 0xFFFF
            co = (co + np.uint32(chk)) & 0xFFFFFFFF
            key = _lfsr_next16v(co)
            code = (X ^ key) & 0xFFFF
            keep = _valid_big5(code)
            if not keep.any():
                break
            orig = orig[keep]
            co = co[keep]  # 壓縮，後續在縮小的陣列上運算
            sum16 = (byte2d + code + byte2e + byte2f + coord1 + coord2 + byte0c + w0e + w10) & 0xFFFF
            co = (co + np.uint32(sum16) + np.uint32(d28) + np.uint32(byte26) + np.uint32(byte27)) & 0xFFFFFFFF
        for j in orig[:20]:
            results.append((int(j), IDX, 0))
    return results

def _decode_with_seed(data, base, cnt, seed0):
    recs = _parse_recs(data, base, cnt)
    count = seed0
    out = []
    for (X, byte0, byte1, byte2, w33, w34, w35, b31, di, ebp8, typ,
         byte2d, byte2e, byte2f, byte26, byte27, d28, coord1, coord2, byte0c, w0e, w10) in recs:
        chk = (byte1 + byte0 + b31 + _s8(byte2) + _s8(w33) + _s8(w34) + _s8(w35) + di + ebp8 - 1) & 0xFFFF
        count = (count + chk) & 0xFFFFFFFF
        key = LFSR(count).next16()
        code = X ^ key
        out.append(code)
        sum16 = (byte2d + code + byte2e + byte2f + coord1 + coord2 + byte0c + w0e + w10) & 0xFFFF
        count = (count + sum16 + d28 + byte26 + byte27) & 0xFFFFFFFF
    return out

def _verify_area(data, off, cnt, recs, seed0):
    """以 seed0 解整區並檢查有效比例；通過回傳 codes，否則 None"""
    codes = _decode_with_seed(data, off + 4, cnt, seed0)
    ratio = sum(1 for c in codes if big5(c) != '\ufffd') / max(1, len(codes))
    return codes if ratio > 0.9 else None

def auto_decode(data, cache=None, allow_full_sweep=False):
    """自動反推 count0 並解碼。
    cache：set of (starter, IDX)，成功組合會加入；下次批次同範本先試快取。
    allow_full_sweep：是否允許最慢的 2^24 全集掃描（預設關閉）。"""
    global np
    if 'np' not in globals():
        import numpy as np
    areas = _find_areas(data)
    areas.sort(key=lambda a: -a[1])
    big_areas = [a for a in areas if a[1] >= 30]
    if not big_areas:
        return None

    # 先解析一次各區記錄，避免重複
    parsed = [(off, cnt, _parse_recs(data, off + 4, cnt)) for off, cnt in big_areas]
    parsed = [(o, c, r) for o, c, r in parsed if len(r) >= 8]

    # 搜尋是「起始字優先」早退，常見起始字（全形空白）會先解開「此致 ○○處…」這類
    # 落款小區，而本文區的起始字是罕用的非文字記錄（0xC3F6 等）排在後面，於是本文被跳過。
    # 因此解出一區後要繼續搜尋其餘各區，全部解出再依檔內順序串接：
    # 函稿的「主旨」與「說明」是兩個區（原廠匯出分別放在「本文」與「函落款」欄），只取一區必漏一段。
    # 含 [＠欄位＠] 佔位符的是範本文字（「會辦單位：[＠會辦單位＠]…」），只在沒有其他區時才採用。
    # 第一區用「起始字優先」跨區搜尋（多數檔案最快）；其餘各區逐區只搜一次，解不出的區不重搜。
    texts, tpl = [], None
    first = _search_areas(data, parsed, cache, allow_full_sweep)
    if first is None:
        return None
    # 其餘區只試快取與優先起始字：罕用起始字那一輪每個解不出的區要 ~0.9 秒，實測對其餘區沒有額外收穫。
    # 例外：若目前只解出範本區（還沒有本文），就要用完整起始字表，否則像法規稿的
    # 「修正「…辦法」」本文（起始字「修」在一般清單）會被跳過。
    # 只對比範本區大的區做完整搜尋（本文通常比範本區大），避免函稿逐區慢搜。
    tpl_cnt = None
    def take(found):
        nonlocal tpl, tpl_cnt
        codes, cnt, off = found
        if _is_template(codes):
            if tpl is None:
                tpl, tpl_cnt = codes, cnt
        else:
            texts.append((off, codes))
    take(first)
    for p in parsed:
        if p[0] == first[2]:
            continue
        rare = not texts and (tpl_cnt is None or p[1] > tpl_cnt)
        r = _search_areas(data, [p], cache, False, rare=rare)
        if r:
            take(r)
    if not texts:
        return tpl
    out = []
    for _off, codes in sorted(texts):
        if out:
            out.append(PARA)
        out.extend(codes)
    return out

PARA = 0x10000      # 區與區之間的分段記號（不在 16 位元字碼範圍內，不會與真字碼衝突）

def _is_template(codes):
    return '[＠' in ''.join(big5(c) for c in codes)

def _is_template(codes):
    return '[＠' in ''.join(big5(c) for c in codes)

def _search_areas(data, parsed, cache, allow_full_sweep, rare=True):
    """在給定的區中依起始字順序搜尋，回傳 (codes, 該區筆數)；都解不出回傳 None。"""
    # 0) 快取命中：只用快取中的 (starter, IDX) 組合，候選量極小
    if cache:
        for starter, IDX in list(cache):
            for off, cnt, recs in parsed:
                res = _scan_starter_all(data, recs, starter, cache_idxs=(IDX,))
                for seed0, IDX2 in res:
                    codes = _verify_area(data, off, cnt, recs, seed0)
                    if codes:
                        return codes, cnt, off

    # 1) 優先起始字（逐起始字早退，找到即停）
    for starter in _STARTERS_PRIORITY:
        for off, cnt, recs in parsed:
            res = _scan_starter_all(data, recs, starter)
            for seed0, IDX in res:
                codes = _verify_area(data, off, cnt, recs, seed0)
                if codes:
                    if cache is not None:
                        cache.add((starter, IDX))
                    return codes, cnt, off

    # 2) 其餘起始字（罕見開頭字；只試已知 IDX，兼顧速度）
    #    8/36/37/39/42/112/116 為 2026-08-02 窮舉實測到的 IDX，未列入就會漏解
    known_idxs = (0, 5, 8, 10, 15, 36, 37, 39, 40, 42, 85, 105, 112, 115, 116, 120, 127)
    for starter in (_STARTERS_REST if rare else ()):
        for off, cnt, recs in parsed:
            res = _scan_starter_all(data, recs, starter, nfilter=8, idx_known=known_idxs)
            for seed0, IDX in res:
                codes = _verify_area(data, off, cnt, recs, seed0)
                if codes:
                    if cache is not None:
                        cache.add((starter, IDX))
                    return codes, cnt, off

    # 3) 全集掃描（預設關閉；僅在明確要求時啟用）
    if allow_full_sweep:
        for off, cnt, recs in parsed[:2]:
            res = _full_sweep_count0(data, recs)
            for seed0, IDX, starter in res:
                codes = _verify_area(data, off, cnt, recs, seed0)
                if codes:
                    return codes, cnt, off
    return None

def big5(code):
    if code == PARA:
        return '\n'
    if code >= 0x100:
        try:
            return bytes([code >> 8, code & 0xFF]).decode('cp950')   # 與原廠匯出一致（‧ 而非 •、含倚天擴充字）
        except Exception:
            return '\ufffd'
    return chr(code) if 0x20 <= code < 0x7f else (' ' if code in (0, 0x0d, 0x0a) else '\ufffd')

# ---------------------------- 重排 ----------------------------
LINE_WIDTH = 38      # 每行字元數（與原系統 .txt 匯出一致）
INDENT = '    '      # 首行縮排（4 空格）

def reflow(text):
    """依版面重排：首行縮排 4 空格、每行 38 字元換行。"""
    lines = []
    pos = 0
    n = len(text)
    first = True
    while pos < n:
        width = LINE_WIDTH - len(INDENT) if first else LINE_WIDTH
        # 找斷點：滿寬度或最後一個字
        end = min(pos + width, n)
        if end < n:
            # 避免在文末前強制斷行（保留最後一段）
            pass
        line = text[pos:end]
        lines.append((INDENT if first else '') + line)
        first = False
        pos = end
    return '\r\n'.join(lines)

def render(codes):
    """字碼轉成輸出文字：各區分段重排，段間空一行。"""
    text = ''.join(big5(c) for c in codes)
    return '\r\n\r\n'.join(reflow(p) for p in text.split('\n'))

# ---------------------------- 批次 ----------------------------
def collect_ods(args):
    files = []
    for a in args:
        if os.path.isdir(a):
            for root, _dirs, names in os.walk(a):
                for nm in names:
                    if nm.lower().endswith('.ods'):
                        files.append(os.path.join(root, nm))
        else:
            files.append(a)
    return files


# 每個 worker 程序各自的種子快取（同程序內跨檔案共享）
_worker_cache = None

def _init_worker():
    global _worker_cache
    _worker_cache = set()

def _long_path(path):
    """Windows 的 260 字元路徑上限：公文資料夾層級很深，分層輸出後很容易超過。
    加上 \\\\?\\ 前綴可解除限制（需絕對路徑）。"""
    if os.name != 'nt':
        return path
    p = os.path.abspath(path)
    if p.startswith('\\\\?\\'):
        return p
    if p.startswith('\\\\'):          # UNC 網路路徑
        return '\\\\?\\UNC\\' + p[2:]
    return '\\\\?\\' + p

def _rel_name(f, root):
    """輸出用的顯示名稱：相對於輸入根目錄的路徑（避免不同資料夾的同名檔互相覆蓋）"""
    if root:
        try:
            rel = os.path.relpath(f, root)
            if not rel.startswith('..'):
                return rel
        except ValueError:      # 跨磁碟機
            pass
    return os.path.basename(f)

def _worker_decode(args):
    f, outdir, root = args
    rel = _rel_name(f, root)
    try:
        data = open(_long_path(f), 'rb').read()
        codes, status = decode_status(data, cache=_worker_cache)
        if codes:
            outpath = os.path.join(outdir, os.path.splitext(rel)[0] + '.txt')
            d = os.path.dirname(outpath)
            if d:
                os.makedirs(_long_path(d), exist_ok=True)
            # newline=''：內容已自帶 \r\n 換行，文字模式會再補一個 \r 變成 \r\r\n（記事本顯示為隔行空白）
            with open(_long_path(outpath), 'w', encoding='utf-8', newline='') as fh:
                fh.write(render(codes) + '\r\n')
            return (rel, status, sum(1 for c in codes if c != PARA), outpath, None)
        return (rel, status, 0, None, None)
    except Exception as e:
        return (rel, 'error', 0, None, str(e))

def batch_decode(files, outdir, workers=None, executor='process', on_result=None, root=None):
    """批次解碼。executor='process'（多行程，約 5 倍加速）或 'thread'（幾乎無加速，僅備援）。
    on_result：每完成一個檔案就呼叫一次（用於即時進度顯示）。
    root：輸入根目錄；有給時輸出會依原資料夾結構分層，避免不同資料夾的同名檔互相覆蓋。
    回傳結果清單 [(相對路徑, status, 字數, 輸出路徑, 錯誤)]。"""
    import concurrent.futures
    if workers is None:
        workers = os.cpu_count() or 4
    os.makedirs(outdir, exist_ok=True)
    results = []
    tasks = [(f, outdir, root) for f in files]

    def collect(it):
        for r in it:
            results.append(r)
            if on_result is not None:
                on_result(r)

    if len(tasks) <= 1 or executor == 'serial':
        _init_worker()
        collect(_worker_decode(t) for t in tasks)
        return results
    if executor == 'thread':
        _init_worker()   # 執行緒共用同一份種子快取
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            collect(ex.map(_worker_decode, tasks))
        return results
    try:
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=workers, initializer=_init_worker) as ex:
            collect(ex.map(_worker_decode, tasks))
    except Exception:
        # 行程池不可用（或中途失效）時退回單執行緒；ex.map 依序回傳，已完成的部分不重做
        _init_worker()
        collect(_worker_decode(t) for t in tasks[len(results):])
    return results

STATUS_LABEL = {
    STATUS_FAST: '快速',
    STATUS_AUTO: '自動反推',
    STATUS_CACHE: '快取',
    STATUS_NOT_JASON: '非捷成格式(可能是試算表/壓縮檔)',
    STATUS_UNKNOWN: '未知變體或檔案損壞',
    'error': '錯誤',
}

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    files = collect_ods(sys.argv[1:])
    root = sys.argv[1] if os.path.isdir(sys.argv[1]) else None
    # 輸出目錄：若第二個參數是目錄且第一個也是目錄，則當作輸出目錄
    outdir = None
    if len(sys.argv) >= 3 and os.path.isdir(sys.argv[1]) and not os.path.isfile(sys.argv[2]):
        # 輸出資料夾不存在就建立；以前會默默改寫到目前工作目錄
        outdir = sys.argv[2]
        os.makedirs(outdir, exist_ok=True)
        files = collect_ods([sys.argv[1]])
    if not files:
        print('沒有找到 .ods 檔案')
        return 1
    if outdir is None:
        outdir = os.getcwd()
    total = len(files)
    print('開始解碼 %d 個檔案（多行程，%d 核）...' % (total, os.cpu_count() or 4))
    counts = {}
    t0 = time.time()

    def report(r):
        base, status, n, outpath, err = r
        counts[status] = counts.get(status, 0) + 1
        done = sum(counts.values())
        if status in (STATUS_FAST, STATUS_AUTO, STATUS_CACHE):
            print('[%d/%d] OK   %s %s (%d 字) -> %s' % (done, total, base, STATUS_LABEL[status], n, outpath))
        elif status == STATUS_NOT_JASON:
            print('[%d/%d] SKIP %s %s' % (done, total, base, STATUS_LABEL[status]))
        else:
            print('[%d/%d] FAIL %s %s%s' % (done, total, base, STATUS_LABEL.get(status, status),
                                            ('：' + err) if err else ''))

    results = batch_decode(sorted(files), outdir, on_result=report, root=root)
    print('耗時 %.1f 秒' % (time.time() - t0))
    ok = sum(counts.get(s, 0) for s in (STATUS_FAST, STATUS_AUTO, STATUS_CACHE))
    print('完成：成功 %d、非捷成 %d、未知/損壞 %d' % (
        ok, counts.get(STATUS_NOT_JASON, 0),
        counts.get(STATUS_UNKNOWN, 0) + counts.get('error', 0)))
    return 0

if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()   # 打包成 exe 後，子行程必須先呼叫此函式
    sys.exit(main())
