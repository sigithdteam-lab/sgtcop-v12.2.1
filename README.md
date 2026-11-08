# SGTCOP — Security Monitor & Webshell Detector

**Versi:** 12.2.1 (portable) · **Lisensi:** GNU GPL v3.0 · **Platform:** Linux (utama)

Scanner keamanan berbasis Python untuk mendeteksi **webshell PHP, backdoor, obfuscation, LFI/RCE, file manager ilegal, privilege escalation, dan hidden file** di server Linux. Menggunakan **11 lapis deteksi** (regex signature + heuristik + semantic + AI Ollama opsional).

**Prinsip desain:** portable 1 folder — script, patterns, report, quarantine, logs, cache semuanya di dalam satu direktori. Cukup `tar` folder itu untuk backup/migrasi.

---


| Komponen | Fungsi |
|----------|--------|
| `sgtcop.py` | Script utama |
| `install.sh` | Installer (install/update/uninstall) |
| `patterns/` | 10 file `.txt` (layer 01–09) |
| `logs/` | Log harian `security_YYYYMMDD.log` |
| `cache/` | Cache file scan (auto-invalidasi saat pattern berubah) |
| `security_report.txt` | Laporan hasil scan |
| `quarantine_recommended.txt` | Rekomendasi karantina (**log only**) |

---

## Instalasi

### Opsi A — Installer (rekomendasi)

```bash
# taruh sgtcop.py + install.sh di /root
sudo ./install.sh
# → install ke /root/sgtcop/run.py + symlink /usr/local/bin/sgtcop

##varian installer
sudo ./install.sh --with-yara     # + download Neo23x0 webshells YARA
sudo ./install.sh --update        # update run.py saja (pertahankan patterns)
sudo ./install.sh --uninstall     # hapus semua
INSTALL_DIR=/opt/sgtcop sudo ./install.sh   # lokasi custom

##tanpa installer
python3 sgtcop.py --version    # jalan langsung

##cara pakai
sudo sgtcop

##mode CLI
sudo sgtcop --once                       # scan sekali
sudo sgtcop --once --deep                # deep (file besar)
sudo sgtcop --once --workers 32          # paralel lebih agresif
sudo sgtcop --once --dir /var/www --dir /home
sudo sgtcop --once --no-ai --no-cache    # tanpa AI & tanpa cache


