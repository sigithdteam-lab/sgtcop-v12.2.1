#!/bin/bash
# ============================================================
# SGTCOP Installer v12.2.2 — Subfolder + run.py
# Source: /root/sgtcop.py + /root/install.sh
# Result: /root/sgtcop/run.py + patterns/ + cache/ + logs/
#
# Usage:
#   sudo ./install.sh              → install ke <script_dir>/sgtcop/
#   sudo ./install.sh --with-yara  → + Neo23x0 patterns
#   sudo ./install.sh --uninstall  → hapus
#   sudo ./install.sh --update     → update run.py saja
# ============================================================
set -euo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; M='\033[0;35m'; N='\033[0m'

# Lokasi source (dimana install.sh berada) = /root
SRC="$(cd "$(dirname "$0")" && pwd)"

# Lokasi instalasi = subfolder 'sgtcop' di samping install.sh
INSTALL_DIR="${INSTALL_DIR:-$SRC/sgtcop}"
BIN_LINK="${BIN_LINK:-/usr/local/bin/sgtcop}"

step() { echo -e "${B}[*]${N} $1"; }
ok()   { echo -e "${G}[✓]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err()  { echo -e "${R}[✗]${N} $1" >&2; exit 1; }

banner() {
    echo -e "${M}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║        SGTCOP Installer v12.2.2                          ║"
    echo "║        Security Monitor & Webshell Detector              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${N}"
}

# ---- Uninstall ----
if [[ "${1:-}" == "--uninstall" ]]; then
    banner
    [[ $EUID -eq 0 ]] || err "Butuh root: sudo $0 --uninstall"
    step "Hentikan systemd"
    systemctl stop sgtcop.timer 2>/dev/null || true
    systemctl disable sgtcop.timer 2>/dev/null || true
    rm -f /etc/systemd/system/sgtcop.service /etc/systemd/system/sgtcop.timer
    systemctl daemon-reload 2>/dev/null || true
    ok "Systemd dibersihkan"

    step "Hapus $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    rm -f "$BIN_LINK"
    # Legacy cleanup
    rm -f /root/security_report.txt /root/quarantine_recommended.txt 2>/dev/null || true
    ok "Uninstalled."

    echo
    echo -e "  ${Y}Source tetap ada:${N}"
    echo -e "    $SRC/sgtcop.py"
    echo -e "    $SRC/install.sh"
    exit 0
fi

# ---- Update ----
if [[ "${1:-}" == "--update" ]]; then
    banner
    [[ $EUID -eq 0 ]] || err "Butuh root: sudo $0 --update"
    [[ -d "$INSTALL_DIR" ]] || err "Belum terinstall."
    [[ -f "$SRC/sgtcop.py" ]] || err "sgtcop.py tidak ditemukan di $SRC"

    step "Backup run.py lama"
    [[ -f "$INSTALL_DIR/run.py" ]] && \
        cp "$INSTALL_DIR/run.py" "$INSTALL_DIR/run.py.bak"

    step "Update run.py (dari sgtcop.py)"
    cp "$SRC/sgtcop.py" "$INSTALL_DIR/run.py"
    chmod 755 "$INSTALL_DIR/run.py"
    ok "Updated ($(wc -l < "$INSTALL_DIR/run.py") lines)"

    step "Verify syntax"
    python3 -c "import ast; ast.parse(open('$INSTALL_DIR/run.py').read())" || err "Syntax error"
    ok "OK"

    step "Reset cache"
    rm -f "$INSTALL_DIR/cache/cache.json"
    ok "Cache reset"

    exit 0
fi

# ---- Options ----
WITH_YARA=false
for arg in "$@"; do
    case "$arg" in
        --with-yara) WITH_YARA=true ;;
        --help|-h)
            banner
            echo "Usage:"
            echo "  sudo $0                # install ke $SRC/sgtcop/"
            echo "  sudo $0 --with-yara    # + Neo23x0 YARA"
            echo "  sudo $0 --update       # update run.py"
            echo "  sudo $0 --uninstall    # hapus instalasi"
            echo
            echo "Env:"
            echo "  INSTALL_DIR  (default: <dir install.sh>/sgtcop)"
            echo "  BIN_LINK     (default: /usr/local/bin/sgtcop)"
            exit 0
            ;;
    esac
done

# ---- Pre-flight ----
banner
[[ $EUID -eq 0 ]] || err "Butuh root: sudo $0"
command -v python3 >/dev/null || err "python3 tidak ditemukan"

PY_MAJOR=$(python3 -c 'import sys;print(sys.version_info[0])')
PY_MINOR=$(python3 -c 'import sys;print(sys.version_info[1])')
if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 6 ]]; }; then
    err "Python 3.6+ dibutuhkan (found $PY_MAJOR.$PY_MINOR)"
fi
ok "python3 $PY_MAJOR.$PY_MINOR"

[[ -f "$SRC/sgtcop.py" ]] || err "sgtcop.py tidak ada di $SRC"

echo
echo -e "  ${C}Source   :${N} $SRC/sgtcop.py"
echo -e "  ${C}Install  :${N} $INSTALL_DIR/"
echo -e "  ${C}Executable:${N} $INSTALL_DIR/run.py"
echo -e "  ${C}Symlink  :${N} $BIN_LINK"
echo

# ---- Create structure ----
step "Membuat direktori $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"/{patterns,cache,logs}
chmod 755 "$INSTALL_DIR" "$INSTALL_DIR"/{cache,logs}
ok "Struktur siap"

# ---- Install: rename sgtcop.py → run.py ----
step "Install run.py (dari sgtcop.py)"
cp "$SRC/sgtcop.py" "$INSTALL_DIR/run.py"
chmod 755 "$INSTALL_DIR/run.py"
ok "run.py ($(wc -l < "$INSTALL_DIR/run.py") lines, $(du -h "$INSTALL_DIR/run.py" | cut -f1))"

# ---- Default patterns ----
install_default_patterns() {
    local d="$INSTALL_DIR/patterns"

    cat > "$d/01_signature.txt" <<'PATEOF'
# Format: LABEL|WEIGHT|REGEX
c99shell|55|\bc99shell\b|\bc99\.php\b
r57shell|55|\br57shell\b|\br57\.php\b
WSO|50|\bWSO\s*v?\d|\bwso\.php\b
b374k|55|\bb374k\b
PhpSpy|55|\bPhpSpy\b
PhpSpyAuth|60|\bphpspypass\b
CrystalShell|50|\bCrystalShell\b
ZyklonShell|50|\bZyklonShell\b
DKShell|50|\bDKShell\b
KA_uShell|50|\bKA_uShell\b
WorseLinux|50|\bWorse\s+Linux\s+Shell\b
ShardShell|45|\bShardShell\b
Gel4y|45|\bGel4y\b
Webadmin|45|\bWebadmin\b.*(?:Shell|PHP)
Loaderz|45|\bLoaderz\b.*WEB
RGOD|45|\bRGOD\b.*webshell
Antichat|45|\bAntichat\b.*shell
PHPShellApp|50|PHPShellApp
MySQLTool|45|mysql_tool\.php
Webr00t|45|\bWebr00t\b
Locus7|45|\bLocus7\b
IndoXploit|60|\bIndoXploit\b
IndoXploitAuto|60|IndoXploit\s*-\s*Auto
0byt3m1n1|60|\b0byt3m1n1\b
ZeroByte|55|\bzerobyte\b
AlfaData|60|ALFA_DATA
AlfaPath|60|alfacgiapi
AlfaConfig|55|alfaconfig_grabber
GYOKKA|55|\bGYOKKA\b
Uchiha|55|Uchiha\s*Terminal|K4NC1L
Janus|50|\bJanus\b.*(?:Shell|Backdoor)
Janus2|50|konzz\.php|setan\.php
Marion001|50|\bMarion001\b|~mysterious\s+who\s+knows~
Sadrazam|55|\bSadrazam\b
SadrazamAvcisi|55|SadrazaM\s+Server\s+Avcisi
AK47|50|\bAK-47\b.*(?:Shell|Security)
AK74|50|AK-74\s+Security\s+Team
H4ckerTR|45|\bH4cker\.tr\b
Shell406|55|Bypass\s+406\s+Not\s+Acceptable
hekerprotzy|55|\bhekerprotzy\b
rootshell|45|\brootshell\b
NinjaShell|55|\{Ninja-Shell\}
NinjaShellEmail|50|wordpresdevnorway@gmail\.com
ECWSFileManager|55|Filemanager\s*\|\s*ECWS
ECWSSalt|60|P5`SU2"6\]NALYR\}
LESuggester|50|linux-exploit-suggester
PrivescExploits|40|\b(pwnkit|dirtypipe|sequoia|netfilter|overlayfs)\b
KaliPrompt|45|㉿|┌──\(
MHLTeam|40|Sincan\s+Exploit|MHL\s+TEAM
KnownBDHost|60|trashcod3/php-backdoor
LiteSpeedBypass|40|X-LSCACHE\s*:\s*off
ImunifyBypass|40|X-Imunify360-Request\s*:\s*bypass
WordfenceBypass|40|WORDFENCE_DISABLE_(?:LIVE_TRAFFIC|FILE_MODS)
ModSecBypass|40|X-Mod-Security
PATEOF

    cat > "$d/02_php_exec.txt" <<'PATEOF'
ExecFromSuperglobal|30|\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$(?:_(?:GET|POST|REQUEST|COOKIE|SERVER))
MultiLineExec|30|\$(?:_(?:GET|POST|REQUEST|COOKIE))\s*\[[^\]]+\]\s*;.*\b(eval|assert|system|exec|include|require)
CookieGate|30|if\s*\(\s*isset\s*\(\s*\$(?:_(?:GET|POST|REQUEST|COOKIE))
NestedEval|40|eval\s*\(\s*eval\s*\(\s*eval\s*\(
EvalRedirect|40|eval\s*\(\s*['"]\?>['"]\s*\.
EvalRawurldecode|40|eval\s*\(\s*rawurldecode
EvalBase64|30|eval\s*\(\s*base64_decode
EvalGzinflate|30|eval\s*\(\s*gzinflate
DecodeExecCombo|30|(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(.*\b(eval|assert|system|exec)
PostCmdField|25|\$_POST\s*\[\s*['"](cmd|c|exec|command|run|shell)['"]
PATEOF

    cat > "$d/03_obfuscation.txt" <<'PATEOF'
TripleBase64|25|base64_decode\s*\(\s*base64_decode\s*\(\s*base64_decode
GzipBase64|25|gzinflate\s*\(.*base64_decode
ReverseGzip|25|strrev\s*\(.*gzinflate
LongBase64|20|base64_decode\s*\(\s*['"]?[A-Za-z0-9+/]{40,}
HexEvalLiteral|30|eval\s*\(\s*['"]\\x[0-9a-f]{2}
PregReplaceE|30|preg_replace\s*\(\s*['"][^'"]*/[a-z]*e[a-z]*['"]
PATEOF

    cat > "$d/04_hex_obfusc.txt" <<'PATEOF'
HexArray|30|\$[A-Za-z0-9_]+\s*=\s*\[\s*"[0-9a-f]{6,}"
GlobalsCall|30|\$GLOBALS\s*\[\s*"[a-zA-Z_]+"\s*\]\s*\[\s*\d+\s*\]\s*\(
HexDecFunc|25|function\s+dec\s*\([^)]*\)\s*\{[^}]*hex2bin
HexAssignEval|25|\$[A-Za-z_]\w*\s*=\s*['"][0-9a-f]{32,}['"]\s*;.*(?:eval|assert)
PATEOF

    cat > "$d/05_filemanager.txt" <<'PATEOF'
MoveUploadedFile|15|move_uploaded_file\s*\(
WriteFromInput|25|file_put_contents\s*\(\s*\$(?:POST|GET|REQUEST)
RecursiveIterator|20|RecursiveDirectoryIterator|RecursiveIteratorIterator
PathTraversal|20|realpath\s*\(\s*\$_GET\s*\[\s*['"]p['"]
FilesUpfArray|15|\$_FILES\s*\[\s*['"](upf|file|upd)['"]
ChmodRecursive|20|chmodRecursive
ScandirFromInput|15|scandir\s*\(\s*\$_GET
PATEOF

    cat > "$d/06_privesc.txt" <<'PATEOF'
BcryptVerify|30|password_verify\s*\(\s*\$_POST
BcryptHash|25|\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}
LiteSpeedBypass|20|litespeed_request_headers
ImunifyBypass|20|imunify360_request_headers
SafeModeRestore|35|ini_restore\s*\(\s*['"]safe_mode
OpenBasedirRestore|35|ini_restore\s*\(\s*['"]open_basedir
LinuxUserns|40|unshare\s*\(\s*CLONE_NEWUSER
WindowsIsAdmin|35|ctypes\.windll\.shell32\.IsUserAnAdmin
WindowsShellExec|35|ShellExecuteW\s*\(
HardcodedHash|25|\$(?:auth_pass|default_hash|HASH)\s*=\s*['"][0-9a-f]{32,}['"]
PATEOF

    cat > "$d/07_rce.txt" <<'PATEOF'
WMICRemote|35|wmic\s+/NODE:
PSEncodedCmd|35|powershell(?:\.exe)?\s+-EncodedCommand
PSSimpleCmd|25|powershell(?:\.exe)?\s+-[cC]\s+
PSReverseShell|40|New-Object\s+System\.Net\.Sockets\.TCPClient
ImpacketPsexec|40|impacket-psexec
RemoteDownload|30|(?:DownloadFile|WebClient)\s*\(\s*['"]https?://
CurlBash|30|curl\s+-[a-zA-Z]*\s*.*\|\s*bash
WgetBash|30|wget\s+.*\|\s*bash
Masscan445|30|masscan\s+.*-p\s*445
PATEOF

    cat > "$d/08_lfi.txt" <<'PATEOF'
IncludeGet|20|include\s*\(\s*\$_GET
IncludePost|20|require\s*\(\s*\$_POST
IncludeRemote|25|include\s*\(\s*['"]https?://
CustomFetcher|25|geturlsinfo\s*\(
EvalImagePayload|30|eval\s*\(\s*file_get_contents\s*\(\s*['"]https?://
PATEOF

    cat > "$d/09_suspicious_names.txt" <<'PATEOF'
shell
cmd
c99
r57
backdoor
webshell
eval
exec
phpshell
adminer
hack
wso
b374k
ninja-shell
ecws
rootshell
merger
dek.php
91sq
filemanager
bd.php
safemode-off
exploit_all_in_one
sodok
alfacgiapi
alfa
indoxploit
0byt3m1n1
zerobyte
gyokka
sumut
barbario
biipass
uchiha
k4nc1l
marion001
sadrazam
ak47shell
ak74
webadmin
phpspy
zyklon
crystal
dkshell
kaushell
c99madd
wacking
tryag
mysql_tool
load_shell
loaderz
rgod
antichat
h4cker
webr00t
locus7
shell406
gel4y
shardshell
smoker
PATEOF

    cat > "$d/09_dangerous_params.txt" <<'PATEOF'
phpspypass
auth_pass
cmd
exec
shell
c
command
run
terminal
PATEOF

    cat > "$d/scan_exts.txt" <<'PATEOF'
.php
.php3
.php4
.php5
.php7
.php8
.php82
.php83
.php84
.phtml
.phps
.phar
.inc
.module
.theme
.engine
.cgi
.pl
.py
.rb
.sh
.bash
.html
.htm
.shtml
.xhtml
.jsp
.jspx
.asp
.aspx
.js
.json
.xml
.css
.htaccess
.user.ini
.env
.txt
.yml
.yaml
.ini
.conf
.go
.rs
.swift
.c
.cpp
.cc
.h
.ps1
.bat
.cmd
.vbs
PATEOF

    cat > "$d/media_exts.txt" <<'PATEOF'
.tiff
.tif
.gif
.png
.jpg
.jpeg
.bmp
.webp
.ico
.mp4
.mp3
.wav
.avi
.mov
.zip
.rar
.7z
.tar
.gz
.pdf
.doc
.docx
PATEOF

    cat > "$d/skip_dirs.txt" <<'PATEOF'
/proc
/sys
/dev
/run
/tmp
/var/tmp
/var/log
/var/cache
/usr/share/doc
/usr/share/man
/var/lib/mysql
/var/lib/postgresql
/var/lib/redis
/etc/ssl
/etc/ssh
/root/.ssh
/snap
/var/lib/docker
PATEOF

    cat > "$d/ransomware_ext.txt" <<'PATEOF'
.sorry
.sorry_exist
.encrypted
.locked
.crypted
.enc
PATEOF

    cat > "$d/ransomware_notes.txt" <<'PATEOF'
HOW_TO_DECRYPT.txt
000___How_to_Recover___000.txt
DECRYPT_INSTRUCTIONS.txt
ransom_note.txt
README_RANSOM.txt
PATEOF
}

step "Install patterns"
if [[ -d "$SRC/patterns" ]] && [[ -n "$(ls -A "$SRC/patterns"/*.txt 2>/dev/null)" ]]; then
    cp "$SRC/patterns"/*.txt "$INSTALL_DIR/patterns/"
    ok "Dari $SRC/patterns ($(ls "$INSTALL_DIR/patterns"/*.txt | wc -l) files)"
else
    warn "patterns/ tidak ditemukan di source, generate defaults..."
    install_default_patterns
    ok "Default patterns ($(ls "$INSTALL_DIR/patterns"/*.txt | wc -l) files)"
fi

# ---- Optional Neo23x0 ----
if [[ "$WITH_YARA" == true ]]; then
    step "Download Neo23x0 signature-base"
    YARA_URL="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar"
    TMP_YARA=$(mktemp)
    if curl -sL --max-time 30 -A "sgtcop-installer/12.2.2" "$YARA_URL" -o "$TMP_YARA" 2>/dev/null; then
        SIZE=$(stat -c%s "$TMP_YARA" 2>/dev/null || stat -f%z "$TMP_YARA")
        if [[ "$SIZE" -lt 100 ]]; then
            warn "Download gagal"
        else
            ok "Diterima: $SIZE bytes"
            grep -oP '\$\w+\s*=\s*"\K[^"\\\n]{3,80}(?=")' "$TMP_YARA" 2>/dev/null \
                | grep -viE '^(http|https|www|php|html|<\?php|<\?=|eval|system|exec|file|content|author|homepage|server|client|version|cookie|session|data|type|address|domain|email|admin|user|password|username|name|value|error|warning|info|debug|test|example|true|false|null|function|return|class|if|else|while|for|var|new|this|window|document|post|get)$' \
                | grep -vE '://' \
                | grep -vE '^\s' \
                | grep -vE '\s{3,}' \
                | grep -vE '^[0-9]+$' \
                | awk 'length($0) >= 3 && length($0) <= 40' \
                | sort -u >> "$INSTALL_DIR/patterns/09_suspicious_names.txt"
            EXTRACTED=$(grep -c . "$INSTALL_DIR/patterns/09_suspicious_names.txt")
            ok "Neo23x0 ditambahkan (total: $EXTRACTED keywords)"
        fi
    else
        warn "Download gagal, skip Neo23x0"
    fi
    rm -f "$TMP_YARA"
fi

# ---- Symlink ----
step "Membuat symlink $BIN_LINK"
ln -sf "$INSTALL_DIR/run.py" "$BIN_LINK"
ok "sgtcop → $INSTALL_DIR/run.py"

# ---- Verify ----
step "Verifikasi"
[[ -x "$INSTALL_DIR/run.py" ]] || err "run.py tidak executable"
[[ -x "$BIN_LINK" ]] || err "Symlink gagal"
python3 -c "import ast; ast.parse(open('$INSTALL_DIR/run.py').read())" || err "Syntax error"
ok "Sintaks OK"

step "Test load patterns"
LOAD_TEST=$(cd "$INSTALL_DIR" && timeout 10 python3 -c "
import sys, os
sys.path.insert(0, '.')
os.chdir('$INSTALL_DIR')
import run as sgtcop
for k in sgtcop.LAYERS:
    n = len(sgtcop.load_regex(sgtcop.LAYER_FILES[k]))
    if n == 0:
        print(f'FAIL: {k}')
        sys.exit(1)
print('OK')
" 2>&1 | tail -1)
if [[ "$LOAD_TEST" == "OK" ]]; then
    ok "Semua pattern layer load OK"
else
    warn "Pattern load: $LOAD_TEST"
fi

step "Cek versi"
VERSION_OUT=$("$BIN_LINK" --version 2>&1 || echo "?")
ok "$VERSION_OUT"

# ---- Done ----
echo
echo -e "${G}╔══════════════════════════════════════════════════════════╗${N}"
echo -e "${G}║           ✓ INSTALASI SELESAI                            ║${N}"
echo -e "${G}╚══════════════════════════════════════════════════════════╝${N}"
echo
echo -e "  ${C}Struktur:${N}"
echo -e "    Source   : $SRC/sgtcop.py"
echo -e "    Install  : $INSTALL_DIR/"
echo -e "    Exec     : $INSTALL_DIR/run.py"
echo -e "    Link     : $BIN_LINK → $INSTALL_DIR/run.py"
echo
echo -e "  ${C}Isi folder $INSTALL_DIR:${N}"
ls -la "$INSTALL_DIR" 2>/dev/null | tail -n +2 | head -20
echo
echo -e "  ${C}Cara pakai:${N}"
echo -e "    ${B}sudo sgtcop${N}                          ${Y}# menu${N}"
echo -e "    ${B}sudo python3 $INSTALL_DIR/run.py${N}   ${Y}# manual${N}"
echo -e "    ${B}sudo sgtcop --once${N}                   ${Y}# scan sekali${N}"
echo -e "    ${B}sudo sgtcop --once --deep${N}            ${Y}# deep scan${N}"
echo -e ""
echo -e "  ${C}Output (semua di 1 folder):${N}"
echo -e "    Report     : $INSTALL_DIR/security_report.txt"
echo -e "    Quarantine : $INSTALL_DIR/quarantine_recommended.txt"
echo -e "    Logs       : $INSTALL_DIR/logs/"
echo -e "    Cache      : $INSTALL_DIR/cache/"
echo -e "    Patterns   : $INSTALL_DIR/patterns/"
echo -e ""
echo -e "  ${C}Backup 1 folder:${N}"
echo -e "    ${B}sudo tar -czf /root/sgtcop-\$(date +%F).tar.gz $INSTALL_DIR${N}"
echo -e ""
echo -e "  ${C}Maintenance:${N}"
echo -e "    ${B}sudo $0 --update${N}       ${Y}# copy ulang sgtcop.py → run.py${N}"
echo -e "    ${B}sudo $0 --uninstall${N}    ${Y}# hapus folder sgtcop/${N}"
echo
