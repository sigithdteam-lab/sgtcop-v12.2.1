#!/usr/bin/env python3
# GNU GPL v3.0 — Copyright (C) 2026 sigithdteam-lab
# sgtcop.py — v12.2.1 STABLE PORTABLE
# ============================================================
# Pattern, report, quarantine, logs, cache = 1 folder dengan script.
# Auto-create. Dedup. YARA filter. ReDoS-safe.
# ============================================================

import os, sys, re, json, hashlib, logging, time, argparse, threading
import shutil, signal, platform
from datetime import datetime
from pathlib import Path
from concurrent.futures import (ThreadPoolExecutor, as_completed,
                                wait, FIRST_COMPLETED)
from collections import defaultdict

__version__ = '12.2.1'


# ============================================================
# PATTERN DIR RESOLVER
# ============================================================
def _resolve_pdir():
    """Auto-detect pattern directory — prioritas folder script."""
    script_dir = Path(__file__).resolve().parent
    candidates = [
        os.environ.get('SGTCOP_PATTERNS'),
        str(script_dir / 'patterns'),
        '/opt/sgtcop/patterns',
        os.path.expanduser('~/.sgtcop/patterns'),
        './patterns',
    ]
    for c in candidates:
        if c and os.path.isdir(c) and os.access(c, os.W_OK):
            return c
    default = str(script_dir / 'patterns')
    try:
        os.makedirs(default, exist_ok=True)
        return default
    except OSError:
        try:
            os.makedirs('/opt/sgtcop/patterns', exist_ok=True)
            return '/opt/sgtcop/patterns'
        except OSError:
            raise SystemExit("Tidak bisa membuat pattern dir")


BASE = Path(__file__).resolve().parent
CFG = {
    'pdir':        _resolve_pdir(),
    'cache':       str(BASE / 'cache' / 'cache.json'),
    'logdir':      str(BASE / 'logs'),
    'report':      str(BASE / 'security_report.txt'),
    'quar':        str(BASE / 'quarantine_recommended.txt'),
    'dirs':        ['/home', '/var/www', '/usr/local/apache/htdocs'],
    'max_n':       10 * 1024 * 1024,
    'max_d':       50 * 1024 * 1024,
    'content':     500_000,
    'workers':     min(16, max(4, (os.cpu_count() or 4) * 2)),
    'ai':          True,
    'ai_url':      'http://localhost:11434/api/generate',
    'ai_model':    'qwen2.5-coder:7b',
    'ai_timeout':  60,
    'ttl':         86400,
    'download_max': 10 * 1024 * 1024,
}

# ---------- Constants ----------
PHP_MAGIC = (b'<?php', b'<?=', b'<?')
MAGIC_MAP = {
    'gif': b'GIF8', 'png': b'\x89PNG', 'jpeg': b'\xff\xd8\xff',
    'bmp': b'BM', 'tiff': b'II*\x00', 'webp': b'RIFF',
    'pdf': b'%PDF', 'zip': b'PK\x03\x04', 'rar': b'Rar!',
    'gzip': b'\x1f\x8b', 'mp4': b'ftyp', 'mp3': b'ID3',
}
SCRIPT_EXTS = frozenset(['.php','.php3','.php4','.php5','.php7','.php8',
                         '.phtml','.phps','.inc','.phar'])
LAYERS = ('signature','php_exec','obfuscation','hex_obfusc',
          'filemanager','privesc','rce','lfi')
LAYER_FILES = {
    'signature': '01_signature', 'php_exec': '02_php_exec',
    'obfuscation': '03_obfuscation', 'hex_obfusc': '04_hex_obfusc',
    'filemanager': '05_filemanager', 'privesc': '06_privesc',
    'rce': '07_rce', 'lfi': '08_lfi',
}
LAYER_WEIGHTS = {
    '01_signature': 55, '02_php_exec': 30, '03_obfuscation': 25,
    '04_hex_obfusc': 30, '05_filemanager': 20, '06_privesc': 25,
    '07_rce': 35, '08_lfi': 25,
}
DOWNLOAD_LAYERS = ['01_signature','02_php_exec','03_obfuscation',
                   '04_hex_obfusc','05_filemanager','06_privesc',
                   '07_rce','08_lfi','09_suspicious_names']

# Pre-compiled
_H_DBL    = re.compile(r'\.(php|phtml|php[0-9])\.(jpg|png|gif|txt|zip|pdf)$', re.I)
_SK_IN    = re.compile(r'\$_(GET|POST|REQUEST|COOKIE)\s*\[')
_SK_DEC   = re.compile(r'(base64_decode|hex2bin|gzinflate|str_rot13|strrev)\s*\(')
_SK_EXEC  = re.compile(r'\b(eval|assert|system|exec|shell_exec|passthru|proc_open)\s*\(')
_AI_REG   = re.compile(r'(eval|assert|system|exec|shell_exec|passthru|'
                       r'popen|proc_open|\$_GET|\$_POST|\$_COOKIE|'
                       r'base64_decode|gzinflate|hex2bin)', re.I)
_AI_JSON  = re.compile(r'\{[^{}]+\}', re.DOTALL)
_YARA_STR = re.compile(r'\$\w+\s*=\s*"([^"\\\n]{3,80})"')

_GENERIC_YARA = frozenset([
    'http','https','www','php','html','<?php','<?=','?>',
    'eval','system','exec','file','content','post','get',
    'true','false','null','function','return','class',
    'if','else','while','for','var','new','this','window',
    'document','user','password','username','name','value',
    'error','warning','info','debug','test','example',
    'author','homepage','server','client','version','cookie',
    'session','data','type','address','domain','email','admin',
])


# ============================================================
# Pattern loader
# ============================================================
def _lines(p):
    try:
        with open(p, errors='ignore') as f:
            return [l.rstrip('\n\r') for l in f
                    if l.strip() and not l.startswith('#')]
    except OSError:
        return []

def load_regex(name, log=None):
    out = []
    for line in _lines(os.path.join(CFG['pdir'], f'{name}.txt')):
        p = line.split('|', 2)
        if len(p) == 3 and p[1].strip().isdigit():
            try:
                out.append((re.compile(p[2], re.I), int(p[1]), p[0].strip()))
                continue
            except re.error:
                pass
        try:
            out.append((re.compile(line, re.I), 25, 'User'))
        except re.error:
            pass
    if log:
        log.info(f"  ✓ {name}.txt: {len(out)}")
    return out

def load_list(name):
    return set(_lines(os.path.join(CFG['pdir'], f'{name}.txt')))


# ============================================================
# Pattern classify + append
# ============================================================
_HINTS = [
    ('07_rce', ('wmic','powershell','impacket','tcpclient','downloadfile',
                'masscan','-encodedcommand','reverse shell')),
    ('06_privesc', ('password_verify','ini_restore','isuseradmin','unshare',
                    'clonenewuser','hekerprotzy','litespeed','imunify',
                    'safe_mode','open_basedir','$2y$','$2a$','$2b$')),
    ('03_obfuscation', ('base64_decode','gzinflate','gzuncompress','str_rot13')),
    ('05_filemanager', ('move_uploaded_file','file_put_contents','scandir',
                        'chmodrecursive','recursivedirectory','$_files',
                        'realpath($_get')),
    ('08_lfi', ('include($_','require($_','geturlsinfo',
                 'include("http',"include('http")),
    ('02_php_exec', ('$_get','$_post','$_cookie','$_request','eval(','assert(',
                     'system(','exec(','shell_exec(','passthru(','popen(','proc_open(')),
]

def _mk_regex(layer, text):
    w = LAYER_WEIGHTS.get(layer, 25)
    label = re.sub(r'\W', '', text.title())[:20] or 'User'
    return {'layer': layer, 'formatted': f'{label}|{w}|{re.escape(text)}',
            'reason': f'Auto → {layer}', 'is_regex': True}

def classify(text):
    t = text.strip()
    low = t.lower()
    p = t.split('|', 2)
    if len(p) == 3 and p[1].strip().isdigit():
        for layer, kws in _HINTS:
            if any(k in p[2].lower() for k in kws):
                return {'layer': layer, 'formatted': t,
                        'reason': f'Advanced → {layer}', 'is_regex': True}
        return {'layer': '01_signature', 'formatted': t,
                'reason': 'Advanced → 01_signature', 'is_regex': True}
    if re.match(r'^["\']?[0-9a-f]{32,}', t, re.I):
        return _mk_regex('04_hex_obfusc', t)
    for layer, kws in _HINTS:
        for kw in kws:
            if kw in low:
                return _mk_regex(layer, t)
    return {'layer': '09_suspicious_names', 'formatted': t,
            'reason': 'Keyword → nama file', 'is_regex': False}

def add_pattern(pattern_dir, text, layer=None):
    t = text.strip()
    if not t:
        return None, 'Kosong'
    if layer:
        if layer.startswith('09_'):
            line = t
        else:
            w = LAYER_WEIGHTS.get(layer, 25)
            label = re.sub(r'\W', '', t.title())[:20] or 'User'
            line = f'{label}|{w}|{re.escape(t)}'
    else:
        info = classify(t)
        layer = info['layer']
        line = info['formatted']
    os.makedirs(pattern_dir, exist_ok=True)
    path = os.path.join(pattern_dir, f'{layer}.txt')
    if os.path.exists(path):
        with open(path) as f:
            if any(line == l.strip() for l in f):
                return None, f'Duplikat di {layer}.txt'
        try:
            shutil.copy2(path, path + '.bak')
        except OSError:
            pass
    try:
        with open(path, 'a') as f:
            f.write(line + '\n')
    except OSError as e:
        return None, f'Write: {e}'
    return {'layer': layer, 'line': line, 'path': path}, None

def pattern_count(pattern_dir, layer):
    p = os.path.join(pattern_dir, f'{layer}.txt')
    return len(_lines(p)) if os.path.exists(p) else 0


# ============================================================
# Download + validation
# ============================================================
def _download(url):
    import urllib.request
    MAX = CFG['download_max']
    try:
        req = urllib.request.Request(url, headers={'User-Agent': f'sgtcop/{__version__}'})
        resp = urllib.request.urlopen(req, timeout=20)
        cl = resp.headers.get('Content-Length')
        if cl:
            try:
                if int(cl) > MAX:
                    return None, f"File terlalu besar ({int(cl)//1024//1024}MB > {MAX//1024//1024}MB)"
            except (ValueError, TypeError):
                pass
        data = resp.read(MAX + 1)
        if len(data) > MAX:
            return None, f"File melebihi {MAX//1024//1024}MB"
        return data.decode('utf-8', 'ignore'), None
    except Exception as e:
        return None, str(e)


def _yara_extract(text):
    """Extract string literals dari YARA — filter noise 9 tingkat."""
    out = set()
    for m in _YARA_STR.finditer(text):
        s = m.group(1).strip()
        if len(s) < 3 or len(s) > 40:
            continue
        if s[0] in '#!/*;' or s.startswith('//'):
            continue
        if '://' in s:
            continue
        if s.count(' ') >= 3:
            continue
        if s != s.strip() or '\n' in s or '\r' in s:
            continue
        low = s.lower()
        if low in _GENERIC_YARA:
            continue
        if not any(c.isalnum() for c in s):
            continue
        if sum(c.isprintable() for c in s) < len(s) * 0.95:
            continue
        if s.isdigit() or s.isspace():
            continue
        out.add(s)
    return out


def _is_safe_regex(pat):
    """Validate regex — reject ReDoS via signal.alarm."""
    if not pat or len(pat) > 500:
        return False
    if re.search(r'\([^)]*[+*][^)]*\)[+*]', pat):
        return False
    try:
        rx = re.compile(pat, re.I)
    except re.error:
        return False
    if not hasattr(signal, 'SIGALRM'):
        return True
    def _timeout(s, f):
        raise TimeoutError()
    try:
        old = signal.signal(signal.SIGALRM, _timeout)
    except (ValueError, OSError):
        return True
    signal.alarm(1)
    try:
        rx.search('a' * 5000)
        rx.search('(a+)+' * 300)
        return True
    except TimeoutError:
        return False
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _save_layer(pdir, layer, lines):
    """Backup + append lines; filter unsafe + dedup + auto-create."""
    os.makedirs(pdir, exist_ok=True)
    p = os.path.join(pdir, f'{layer}.txt')
    existing = set(_lines(p)) if os.path.exists(p) else set()
    if os.path.exists(p):
        try:
            shutil.copy2(p, p + '.bak')
        except OSError:
            pass
    safe, dropped, dups = [], 0, 0
    for l in lines:
        l = l.rstrip()
        if not l:
            continue
        if layer.startswith('09_'):
            if l in existing:
                dups += 1
                continue
            safe.append(l); existing.add(l)
            continue
        parts = l.split('|', 2)
        if len(parts) == 3 and parts[1].strip().isdigit():
            if l in existing:
                dups += 1
                continue
            if _is_safe_regex(parts[2]):
                safe.append(l); existing.add(l)
            else:
                dropped += 1
        elif '|' in l:
            dropped += 1
        else:
            if l in existing:
                dups += 1
                continue
            if _is_safe_regex(l):
                safe.append(l); existing.add(l)
            else:
                dropped += 1
    try:
        with open(p, 'a') as f:
            for l in safe:
                f.write(l + '\n')
    except OSError as e:
        return f"Gagal tulis ke {p}: {e}", 0
    msg = f"✓ {len(safe)} ditambahkan ke {layer}.txt"
    extras = []
    if dups: extras.append(f"{dups} duplikat")
    if dropped: extras.append(f"{dropped} ReDoS/format salah")
    if extras:
        msg += f" ({', '.join(extras)} dilewati)"
    msg += f"\n  File: {p}"
    return msg, len(safe)


# ============================================================
# Menu Download
# ============================================================
def _menu_download():
    print("\n" + "═" * 55)
    print("  DOWNLOAD PATTERN DARI INTERNET")
    print("═" * 55)
    print(f"  Pattern dir: {CFG['pdir']}")
    print("""
  [1] Custom URL — pattern .txt (format sgtcop)
  [2] Custom URL — YARA rule (extract strings)
  [3] Neo23x0 signature-base (webshells YARA)
  [0] Kembali
""")
    c = input("  Pilih: ").strip()
    if c == '0':
        return
    url, is_yara, label = None, False, ''
    if c == '1':
        url = input("  URL .txt: ").strip()
        label = '.txt'
    elif c == '2':
        url = input("  URL .yar: ").strip()
        is_yara, label = True, 'YARA'
    elif c == '3':
        url = ("https://raw.githubusercontent.com/Neo23x0/"
               "signature-base/master/yara/thor-webshells.yar")
        is_yara, label = True, 'Neo23x0 signature-base'
        print(f"  URL: {url}")
    else:
        return
    if not url:
        print("  ✗ URL kosong"); return
    if not url.startswith(('http://', 'https://')):
        print("  ✗ Hanya http:// atau https:// yang didukung")
        return
    print(f"\n  ⏳ Downloading {label}...")
    data, err = _download(url)
    if err:
        print(f"  ✗ Gagal: {err}"); return
    print(f"  ✓ Diterima: {len(data)} bytes")
    if is_yara:
        strings = _yara_extract(data)
        if not strings:
            print("  ⚠ Tidak ada string literal berguna ditemukan"); return
        items = sorted(strings)
        print(f"\n  ✓ {len(items)} strings (setelah filter). Preview:")
        for s in items[:8]:
            print(f"    {s[:70]}")
        if len(items) > 8:
            print(f"    ... +{len(items)-8} more")
        if input("\n  Simpan ke 09_suspicious_names.txt? [y/N]: ").lower() != 'y':
            print("  ✗ Batal."); return
        msg, _ = _save_layer(CFG['pdir'], '09_suspicious_names',
                              [s.lower() for s in items])
    else:
        lines = [l.strip() for l in data.split('\n')
                 if l.strip() and not l.startswith('#')]
        if not lines:
            print("  ⚠ File kosong"); return
        print(f"\n  ✓ {len(lines)} lines. Preview:")
        for l in lines[:8]:
            print(f"    {l[:70]}")
        if len(lines) > 8:
            print(f"    ... +{len(lines)-8} more")
        print(f"\n  Simpan ke layer:")
        for i, l in enumerate(DOWNLOAD_LAYERS, 1):
            cnt = pattern_count(CFG['pdir'], l)
            print(f"    [{i}] {l}.txt  ({cnt})")
        try:
            n = int(input("  Pilih [1-9]: "))
            if not (1 <= n <= len(DOWNLOAD_LAYERS)):
                raise ValueError
            layer = DOWNLOAD_LAYERS[n - 1]
        except (ValueError, IndexError):
            print("  ✗ Invalid."); return
        msg, _ = _save_layer(CFG['pdir'], layer, lines)
    print(f"\n  {msg}")
    print(f"  💡 Pattern aktif pada scan berikutnya")


# ============================================================
# Menu Systemd
# ============================================================
_SVC_PATH = "/etc/systemd/system/sgtcop.service"
_TMR_PATH = "/etc/systemd/system/sgtcop.timer"

_SVC_UNIT = """[Unit]
Description=SGTCOP Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart={bin} --once --deep
User=root
StandardOutput=journal
StandardError=journal
"""

_TMR_UNIT = """[Unit]
Description=SGTCOP auto-scan every 6 hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""

def _sh(cmd):
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

def _menu_systemd():
    if platform.system() != 'Linux':
        print(f"  ✗ Systemd hanya tersedia di Linux (detected: {platform.system()})")
        return
    if os.geteuid() != 0:
        print("  ✗ Butuh root. Jalankan: sudo sgtcop")
        return
    installed = os.path.exists(_SVC_PATH) and os.path.exists(_TMR_PATH)
    active = ('active' in _sh(['systemctl', 'is-active', 'sgtcop.timer']).lower()
              if installed else False)
    print(f"""
  Status  : {'✓ INSTALLED' if installed else '✗ NOT INSTALLED'}
  Timer   : {'✓ AKTIF' if active else '✗ TIDAK AKTIF'}
  Service : {_SVC_PATH}
  Timer   : {_TMR_PATH}
  Jadwal  : setiap 6 jam (00, 06, 12, 18)

  [1] Install service + timer
  [2] Uninstall
  [3] Start timer
  [4] Stop timer
  [5] Status detail
  [6] Lihat log (journalctl)
  [0] Kembali
""")
    c = input("  Pilih: ").strip()
    if c == '0':
        return
    bin_p = os.path.realpath(sys.argv[0]) if sys.argv[0] else ''
    if not os.path.exists(bin_p):
        bin_p = os.path.realpath(__file__)
    if c == '1':
        try:
            with open(_SVC_PATH, 'w') as f:
                f.write(_SVC_UNIT.format(bin=bin_p))
            with open(_TMR_PATH, 'w') as f:
                f.write(_TMR_UNIT)
        except OSError as e:
            print(f"  ✗ Write gagal: {e}"); return
        _sh(['systemctl', 'daemon-reload'])
        out = _sh(['systemctl', 'enable', '--now', 'sgtcop.timer'])
        print(f"  ✓ Terinstall & aktif")
        print(f"  Binary: {bin_p}")
        if out:
            print(f"  {out}")
    elif c == '2':
        _sh(['systemctl', 'disable', '--now', 'sgtcop.timer'])
        for p in (_SVC_PATH, _TMR_PATH):
            if os.path.exists(p):
                try: os.remove(p)
                except OSError: pass
        _sh(['systemctl', 'daemon-reload'])
        print("  ✓ Uninstalled")
    elif c == '3':
        print("  " + (_sh(['systemctl', 'start', 'sgtcop.timer']) or 'started'))
    elif c == '4':
        print("  " + (_sh(['systemctl', 'stop', 'sgtcop.timer']) or 'stopped'))
    elif c == '5':
        print(_sh(['systemctl', 'status', 'sgtcop.timer', '--no-pager']))
    elif c == '6':
        print(_sh(['journalctl', '-u', 'sgtcop.service', '-n', '50', '--no-pager']))


# ============================================================
# Monitor
# ============================================================
class Monitor:
    def __init__(self, mode='normal', no_cache=False):
        self.mode = mode
        self.no_cache = no_cache
        self._setup()
        self.ph = self._pat_hash()
        self._load_patterns()
        self._load_cache()
        self._lock = threading.Lock()
        self.findings = {k: [] for k in (
            'critical','suspicious','hidden','skeleton','ai',
            'signature','quarantine','ransomware')}
        self.stats = {'scanned':0,'skip':0,'size':0,'start':0,'elapsed':0}
        self._seen = set()
        self._ai_ok = self._probe_ai()

    def _setup(self):
        for d in (CFG['logdir'], os.path.dirname(CFG['cache']), CFG['pdir']):
            Path(d).mkdir(parents=True, exist_ok=True)
        lf = f"{CFG['logdir']}/security_{datetime.now():%Y%m%d}.log"
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
            handlers=[logging.FileHandler(lf), logging.StreamHandler()])
        self.log = logging.getLogger('sgtcop')

    def _pat_hash(self):
        h = hashlib.md5()
        try:
            for f in sorted(os.listdir(CFG['pdir'])):
                if f.endswith('.txt'):
                    try:
                        with open(os.path.join(CFG['pdir'], f), 'rb') as fp:
                            h.update(fp.read())
                    except OSError:
                        pass
        except OSError:
            pass
        return h.hexdigest()

    def _load_patterns(self):
        self.log.info(f"Pattern dir: {CFG['pdir']}")
        self.log.info("Memuat patterns...")
        self.rx = {k: load_regex(LAYER_FILES[k], self.log) for k in LAYERS}
        self.lst = {
            'names':     load_list('09_suspicious_names'),
            'params':    load_list('09_dangerous_params'),
            'scan_ext':  frozenset(load_list('scan_exts')),
            'media_ext': frozenset(load_list('media_exts')),
            'skip':      tuple(load_list('skip_dirs')),
            'rans_ext':  tuple(load_list('ransomware_ext')),
            'rans_note': load_list('ransomware_notes'),
        }

    def _load_cache(self):
        if self.no_cache:
            self._cache = {}
            return
        try:
            if os.path.exists(CFG['cache']):
                with open(CFG['cache']) as f:
                    d = json.load(f)
                if d.get('ph') == self.ph:
                    self._cache = d.get('files', {})
                    return
                self.log.info("  🔄 Pattern berubah → cache reset")
        except Exception:
            pass
        self._cache = {}

    def _save_cache(self):
        if self.no_cache:
            return
        try:
            now = time.time()
            p = {k: v for k, v in self._cache.items()
                 if now - v.get('t', 0) < CFG['ttl']}
            with open(CFG['cache'], 'w') as f:
                json.dump({'ph': self.ph, 'files': p}, f)
        except Exception:
            pass

    def _skip(self, p):
        return p.startswith(self.lst['skip'])

    def _iter(self, root):
        stack = [root]
        while stack:
            d = stack.pop()
            if self._skip(d):
                continue
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                ext = os.path.splitext(e.name)[1].lower()
                                if ext in self.lst['scan_ext'] or ext in self.lst['media_ext']:
                                    yield e.path, ext, e.stat(follow_symlinks=False).st_size
                        except OSError:
                            continue
            except OSError:
                continue

    def _probe_ai(self):
        if not CFG['ai']:
            return False
        try:
            import urllib.request as U
            base = CFG['ai_url'].rsplit('/api/', 1)[0]
            r = U.urlopen(U.Request(f'{base}/api/tags', method='GET'), timeout=3)
            tags = json.loads(r.read())
            if any('qwen' in m.get('name','').lower() for m in tags.get('models',[])):
                self.log.info("  ✓ Ollama AI")
                return True
        except Exception:
            pass
        return False

    def _analyze_ai(self, path, content, weak):
        if not self._ai_ok or len(weak) >= 3:
            return None
        lines = content.split('\n')
        regions, seen = [], set()
        for i, ln in enumerate(lines):
            if _AI_REG.search(ln):
                if any(abs(i-s) <= 3 for s in seen):
                    continue
                a, b = max(0, i-3), min(len(lines), i+4)
                regions.append(f"[{i+1}]\n" + '\n'.join(lines[a:b]))
                seen.add(i)
                if len(regions) >= 5:
                    break
        if not regions:
            return None
        rt = '\n'.join(f"  - {r[:80]}" for r in weak[:3])
        prompt = (f"PHP security analyze.\nFile: {os.path.basename(path)}\n"
                  f"Signals:\n{rt}\nCode:\n{chr(10).join(regions)}\n\n"
                  'JSON only: {"malicious":bool,"confidence":0-100,'
                  '"reason":"brief","attack_type":"webshell|backdoor|'
                  'lfi|rce|obfuscation|legitimate"}')
        try:
            import urllib.request as U
            req = U.Request(CFG['ai_url'],
                data=json.dumps({'model': CFG['ai_model'], 'prompt': prompt,
                    'stream': False, 'options': {'temperature': 0.1,
                    'num_predict': 200}}).encode(),
                headers={'Content-Type': 'application/json'})
            r = U.urlopen(req, timeout=CFG['ai_timeout'])
            m = _AI_JSON.search(json.loads(r.read()).get('response', ''))
            if not m:
                return None
            d = json.loads(m.group())
            if 'malicious' not in d:
                return None
            return {'malicious': bool(d['malicious']),
                    'confidence': int(d.get('confidence', 50)),
                    'reason': str(d.get('reason',''))[:200],
                    'attack_type': str(d.get('attack_type','unknown'))}
        except Exception as e:
            self.log.debug(f"AI: {e}")
            return None

    def scan(self, path, ext, size):
        if path in self._seen:
            return
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        c = self._cache.get(path)
        if c and c.get('s') == size and abs(mtime - c.get('m', 0)) < 1:
            with self._lock:
                self.stats['skip'] += 1
            return
        max_sz = CFG['max_d'] if self.mode == 'deep' else CFG['max_n']
        if size > max_sz:
            self._cache[path] = {'t': time.time(), 's': size, 'm': mtime}
            return
        try:
            with open(path, 'rb') as f:
                head = f.read(16384)
                raw = f.read(CFG['content'])
        except OSError:
            return
        content = raw.decode('utf-8', errors='ignore') if raw else ''
        fhash = hashlib.md5(head + raw[:4096]).hexdigest()
        is_media = ext in self.lst['media_ext']
        is_script = ext in self.lst['scan_ext'] or ext in SCRIPT_EXTS
        base = os.path.basename(path)
        reasons, score, crit = [], 0, False
        h_r, h_s, h_c = self._hidden(ext, head, base, is_media, is_script)
        reasons += h_r; score += h_s; crit |= h_c
        if is_media and not is_script:
            self._finalize(path, size, fhash, reasons, score, crit)
            self._cache[path] = {'t': time.time(), 's': size, 'm': mtime}
            return
        if content and content.strip():
            for layer in LAYERS:
                for rx, w, lb in self.rx[layer]:
                    if rx.search(content):
                        reasons.append(lb)
                        score += w
                        crit |= w >= 30
            low = path.lower()
            for nm in self.lst['names']:
                if nm and nm in low:
                    reasons.append(f"NAME:{nm}")
                    score += 15
                    break
            sk = 0
            if _SK_IN.search(content):
                if _SK_EXEC.search(content):
                    sk += 40
                    if _SK_DEC.search(content):
                        sk += 40
            if sk:
                reasons.append(f"SKELETON:{sk}")
                score += sk; crit = True
            if 0 < len(reasons) <= 2:
                ai = self._analyze_ai(path, content, reasons)
                if ai and ai['malicious']:
                    reasons.append(f"AI:{ai['attack_type']}({ai['confidence']}%)")
                    score += 30; crit = True
                    with self._lock:
                        self.findings['ai'].append({'path': path, 'result': ai})
        self._finalize(path, size, fhash, reasons, score, crit)
        self._cache[path] = {'t': time.time(), 's': size, 'm': mtime}

    def _hidden(self, ext, head, base, is_media, is_script):
        r, s, c = [], 0, False
        if is_media:
            if head.startswith(PHP_MAGIC):
                r.append(f"HIDDEN_PHP:{ext}"); s += 60; c = True
            elif any(p in head[:1024] for p in PHP_MAGIC):
                r.append("HIDDEN_PHP:1KB"); s += 50; c = True
        if is_script:
            for name, magic in MAGIC_MAP.items():
                if head.startswith(magic):
                    r.append(f"POLYGLOT:{name}"); s += 55; c = True
                    break
        if _H_DBL.search(base):
            r.append("DOUBLE_EXT"); s += 40; c = True
        if '\x00' in base:
            r.append("NULL_BYTE"); s += 70; c = True
        if base.startswith('.') and ext in SCRIPT_EXTS:
            r.append("DOT_SCRIPT"); s += 30
        return r, s, c

    def _finalize(self, path, size, fhash, reasons, score, critical):
        with self._lock:
            self._seen.add(path)
            if not reasons:
                return
            if score >= 80:   lvl = 'CRITICAL'
            elif score >= 55: lvl = 'HIGH'
            elif score >= 30: lvl = 'MEDIUM'
            else:             lvl = 'LOW'
            info = {'path': path, 'reasons': reasons[:10], 'hash': fhash,
                    'size': size, 'score': score, 'level': lvl}
            if lvl in ('CRITICAL', 'HIGH'):
                self.findings['critical'].append(info)
                self.findings['quarantine'].append(info)
                self.log.warning(f"  💀 [{lvl}] {path} ({score})")
            else:
                self.findings['suspicious'].append(info)
            for r in reasons:
                if r.startswith('HIDDEN'): self.findings['hidden'].append(path)
                if r.startswith('SKELETON'): self.findings['skeleton'].append(path)
                if ':' in r and r.split(':')[0] not in ('NAME','HIDDEN','SKELETON','AI'):
                    self.findings['signature'].append(path)

    def _ransomware(self):
        for d in CFG['dirs']:
            if not os.path.isdir(d): continue
            counts = defaultdict(int)
            stack = [d]
            while stack:
                cur = stack.pop()
                if self._skip(cur): continue
                try:
                    with os.scandir(cur) as it:
                        for e in it:
                            try:
                                if e.is_dir(follow_symlinks=False):
                                    stack.append(e.path)
                                elif e.is_file(follow_symlinks=False):
                                    low = e.name.lower()
                                    for ex in self.lst['rans_ext']:
                                        if low.endswith(ex):
                                            counts[ex] += 1; break
                                    if e.name in self.lst['rans_note']:
                                        self.findings['ransomware'].append(f"{e.name} @ {cur}")
                            except OSError:
                                continue
                except OSError:
                    continue
            for ex, n in counts.items():
                if n: self.findings['ransomware'].append(f"{n}× {ex} in {d}")

    def run(self):
        self.stats['start'] = time.time()
        self.log.info("=" * 60)
        self.log.info(f"SCAN | {self.mode.upper()} | workers={CFG['workers']}")
        self.log.info("=" * 60)
        dirs = [d for d in CFG['dirs'] if os.path.isdir(d)]
        if not dirs:
            self.log.warning("Tidak ada directory valid"); return
        total = 0
        with ThreadPoolExecutor(max_workers=CFG['workers']) as pool:
            futures = set()
            for d in dirs:
                for path, ext, size in self._iter(d):
                    while len(futures) >= CFG['workers'] * 4:
                        done, futures = wait(futures, return_when=FIRST_COMPLETED)
                        self._consume(done)
                    futures.add(pool.submit(self.scan, path, ext, size))
                    total += 1
                    if total % 200 == 0:
                        print(f"\r  scanned: {total}", end='', file=sys.stderr)
            print(f"\r  scanned: {total} files   ", file=sys.stderr)
            for fut in as_completed(futures):
                self._consume({fut})
        self._ransomware()
        self.stats['elapsed'] = time.time() - self.stats['start']
        self._save_cache()
        self._reports()
        self._summary()

    def _consume(self, done):
        for f in done:
            try: f.result()
            except Exception: pass

    def _reports(self):
        s = self.stats
        lines = [
            "=" * 70,
            f"SECURITY SCAN — {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"Mode: {self.mode.upper()} | Workers: {CFG['workers']}",
            "=" * 70, "",
            f"Files scanned   : {s['scanned']}",
            f"Cache skip      : {s['skip']}",
            f"Total size      : {s['size'] / (1024*1024):.2f} MB",
            f"Elapsed         : {s['elapsed']:.1f}s",
            f"Throughput      : {s['scanned'] / max(s['elapsed'], 0.01):.1f} files/s",
            "",
            f"💀 Critical    : {len(self.findings['critical'])}",
            f"🎭 Hidden      : {len(self.findings['hidden'])}",
            f"🧠 Skeleton    : {len(self.findings['skeleton'])}",
            f"🎯 Signature   : {len(self.findings['signature'])}",
            f"🤖 AI          : {len(self.findings['ai'])}",
            f"🦠 Ransomware  : {len(self.findings['ransomware'])}",
            f"📋 Quarantine  : {len(self.findings['quarantine'])}",
            "",
        ]
        if self.findings['critical']:
            lines += ["CRITICAL FILES:", "-" * 70]
            for i, c in enumerate(self.findings['critical'][:40], 1):
                lines.append(f"{i}. [{c['level']}] {c['path']} ({c['score']})")
                lines += [f"   - {r}" for r in c['reasons'][:5]]
                lines.append("")
        try:
            with open(CFG['report'], 'w') as f:
                f.write('\n'.join(lines))
        except Exception as e:
            self.log.error(f"Report: {e}")
        q = ["=" * 70, "QUARANTINE RECOMMENDATIONS (LOG ONLY)",
             f"Total: {len(self.findings['quarantine'])}", "=" * 70, ""]
        for i, r in enumerate(self.findings['quarantine'], 1):
            q.append(f"[{i}] {r['path']} — {r['level']} ({r['score']})")
            q += [f"      - {x}" for x in r['reasons'][:5]]
            q.append("")
        try:
            with open(CFG['quar'], 'w') as f:
                f.write('\n'.join(q))
        except Exception as e:
            self.log.error(f"Quar: {e}")

    def _summary(self):
        print("\n" + "=" * 60)
        print(f"SELESAI dalam {self.stats['elapsed']:.1f}s")
        print(f"  Scanned    : {self.stats['scanned']} ({self.stats['skip']} cached)")
        print(f"  💀 Critical: {len(self.findings['critical'])}")
        print(f"  📋 Quarant.: {len(self.findings['quarantine'])}")
        print(f"  📄 Report  : {CFG['report']}")
        print(f"  📋 Quar    : {CFG['quar']}")
        print("=" * 60)


# ============================================================
# Menu helpers
# ============================================================
def _ask_folder():
    print(f"\n📂 Default: {', '.join(CFG['dirs'])}")
    print("   (kosong=default, pisah koma untuk multiple)")
    inp = input("   Folder: ").strip()
    if not inp:
        return list(CFG['dirs'])
    dirs = [d.strip() for d in inp.split(',') if d.strip()]
    ok = [d for d in dirs if os.path.isdir(d)]
    bad = [d for d in dirs if not os.path.isdir(d)]
    if bad:
        print(f"   ⚠ Diabaikan: {', '.join(bad)}")
    return ok or list(CFG['dirs'])

def _run(mode):
    old = CFG['dirs']
    CFG['dirs'] = _ask_folder()
    try:
        Monitor(mode).run()
    finally:
        CFG['dirs'] = old

def _menu_add():
    print("\n" + "═" * 55)
    print("  TAMBAH PATTERN / KEYWORD")
    print("═" * 55)
    print(f"  Pattern dir: {CFG['pdir']}")
    print("""
Contoh: anjing       → keyword nama file (L9)
        eval($_POST  → PHP exec (L2)
        Ninja-Shell  → brand signature (L1)
        wmic /NODE:  → RCE (L7)
        MyShell|60|\\bMyShell\\b → advanced
""")
    t = input("Pattern: ").strip()
    if not t:
        print("  ✗ Batal."); return
    info = classify(t)
    print(f"\n🔍 Auto: {info['layer']}.txt")
    print(f"   Format: {info['formatted']}")
    print("\n[Y] Terima  [L] Layer manual  [N] Batal")
    c = input("Pilih: ").strip().upper()
    if c == 'N':
        print("  ✗ Batal."); return
    layer = None
    if c == 'L':
        layers = ['01_signature','02_php_exec','03_obfuscation','04_hex_obfusc',
                  '05_filemanager','06_privesc','07_rce','08_lfi',
                  '09_suspicious_names','09_dangerous_params']
        for i, l in enumerate(layers, 1):
            print(f"   [{i:>2}] {l}.txt ({pattern_count(CFG['pdir'], l)})")
        try:
            n = int(input("Pilih: "))
            if not (1 <= n <= len(layers)):
                raise ValueError
            layer = layers[n - 1]
        except (ValueError, IndexError):
            print("  ✗ Invalid."); return
    res, err = add_pattern(CFG['pdir'], t, layer)
    if err:
        print(f"\n  ✗ {err}"); return
    print(f"\n  ✅ Tersimpan ke {res['layer']}.txt")
    print(f"     Line : {res['line']}")
    print(f"     Path : {res['path']}")
    print(f"     Total: {pattern_count(CFG['pdir'], res['layer'])} entries")

def _analyze():
    f = input("  File: ").strip()
    if not os.path.isfile(f):
        print(f"  ✗ Bukan file: {f}"); return
    print(f"\n  Analisa: {f}")
    m = Monitor('normal')
    m.scan(f, os.path.splitext(f)[1].lower(), os.path.getsize(f))
    hits = m.findings['critical'] + m.findings['suspicious']
    if hits:
        for h in hits:
            print(f"\n  [{h['level']}] score={h['score']}")
            for r in h['reasons']:
                print(f"     - {r}")
    else:
        print("  ✅ Bersih.")

def _show(path):
    if not os.path.exists(path):
        print(f"  ✗ Kosong: {path}"); return
    try:
        with open(path) as f:
            c = f.read()
        print(c[:5000])
        if len(c) > 5000:
            print(f"\n... (truncated, total {len(c)}B)")
    except Exception as e:
        print(f"  ✗ {e}")

HELP = f"""
SGTCOP v{__version__} — Security Monitor & Webshell Detector

Pattern dir: {CFG['pdir']}
Report     : {CFG['report']}
Quarantine : {CFG['quar']}

DETEKSI (11 layer):
  L0  Hidden file (magic byte, polyglot, stego)
  L1  Signature brand  (01_signature.txt)
  L2  PHP exec         (02_php_exec.txt)
  L3  Obfuscation      (03_obfuscation.txt)
  L4  Hex obfuscation  (04_hex_obfusc.txt)
  L5  File manager     (05_filemanager.txt)
  L6  Priv escalation  (06_privesc.txt)
  L7  RCE / lateral    (07_rce.txt)
  L8  LFI / RFI        (08_lfi.txt)
  L9  Nama & parameter (09_*.txt)
  L10 Semantic skeleton
  L11 AI Ollama

MENU:
  [6] Add Pattern      — tambah pattern manual / auto-classify
  [7] Download Pattern — download dari URL / YARA / Neo23x0
  [8] Systemd Service  — install timer auto-scan tiap 6 jam

CLI:
  python3 sgtcop.py --once
  python3 sgtcop.py --once --deep
  python3 sgtcop.py --once --workers 32
  python3 sgtcop.py --once --dir /home --dir /var/www
  python3 sgtcop.py --once --no-ai --no-cache
"""

def _menu():
    while True:
        print(f"""
╔══════════════════════════════════════════════════════════╗
║    SGTCOP v{__version__} — STABLE PORTABLE                 ║
║    Pattern : {CFG['pdir'][:43]:<43}  ║
║    Report  : {CFG['report'][:43]:<43}  ║
╚══════════════════════════════════════════════════════════╝

  [1] Quick Scan     [2] Deep Scan      [3] Analyze File
  [4] View Report    [5] Quarantine     [6] Add Pattern
  [7] Download Ptrn  [8] Systemd        [9] Help
  [0] Exit
""")
        try:
            c = input("  Pilih: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Bye."); break
        if c == '1':
            _run('normal'); input("\n  [Enter]...")
        elif c == '2':
            _run('deep'); input("\n  [Enter]...")
        elif c == '3':
            _analyze(); input("\n  [Enter]...")
        elif c == '4':
            _show(CFG['report']); input("\n  [Enter]...")
        elif c == '5':
            _show(CFG['quar']); input("\n  [Enter]...")
        elif c == '6':
            _menu_add(); input("\n  [Enter]...")
        elif c == '7':
            _menu_download(); input("\n  [Enter]...")
        elif c == '8':
            _menu_systemd(); input("\n  [Enter]...")
        elif c == '9':
            print(HELP); input("\n  [Enter]...")
        elif c == '0':
            print("  Goodbye."); break

def _cli():
    p = argparse.ArgumentParser(prog='sgtcop.py')
    p.add_argument('--version', action='version', version=f'sgtcop {__version__}')
    p.add_argument('--once', action='store_true')
    p.add_argument('--deep', action='store_true')
    p.add_argument('--workers', type=int, default=CFG['workers'])
    p.add_argument('--no-ai', action='store_true')
    p.add_argument('--no-cache', action='store_true')
    p.add_argument('--dir', action='append')
    a = p.parse_args()
    CFG['workers'] = max(1, a.workers)
    CFG['ai'] = not a.no_ai
    if a.dir:
        CFG['dirs'] = a.dir
    Monitor('deep' if a.deep else 'normal', no_cache=a.no_cache).run()

def main():
    if len(sys.argv) > 1:
        _cli()
    else:
        try: _menu()
        except KeyboardInterrupt: print("\n  Interrupted.")

if __name__ == '__main__':
    main()
