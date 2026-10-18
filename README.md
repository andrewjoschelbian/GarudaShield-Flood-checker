# GarudaShield Flood-check

Tools deteksi flood/DDoS sederhana berbasis Python (stdlib only, tanpa dependency tambahan). Dibuat oleh **@andrewjoschelbian**.

GarudaShield Flood-check punya dua mode:

| Mode | Fungsi | Butuh Root? |
|---|---|---|
| `monitor` | Sniff trafik lokal, deteksi flood **ke IP mesin ini** | Ya (Linux) |
| `probe` | Cek kesehatan IP remote dari luar (latensi + loss) | Opsional* |

\* `--ping` (ICMP echo) butuh root; TCP probe tidak.

---

## Cara Pakai

### 1. Monitor (deteksi flood ke IP sendiri)

```bash
sudo python3 floodcheck.py monitor
sudo python3 floodcheck.py monitor --iface eth0
sudo python3 floodcheck.py monitor --thresh 5000 --top 20
```

Tampilkan tabel live **IP sumber → pps → protokol dominan**, refresh tiap detik:

```
IP sumber        pps   proto dominan  status
103.147.8.21    8432             UDP  !!! FLOOD
185.220.1.10     412             TCP  aneh
```

- Alert `FLOOD` + bunyi bel kalau satu sumber IP melewati threshold (default 2000 pps)
- Khusus TCP hanya menghitung paket **SYN** — SYN flood langsung kelihatan, tidak tergenap koneksi normal
- Kunci threshold: `--thresh <pps>`, jumlah baris: `--top <n>`, interface: `--iface <nama>`

### 2. Probe (cek IP remote dari luar)

```bash
python3 floodcheck.py probe 10.0.0.5 --port 443
sudo python3 floodcheck.py probe 10.0.0.5 --port 443 --ping
python3 floodcheck.py probe 10.0.0.5 --count 30 --interval 0.2 --timeout 3
```

```
=== hasil probe ===
  TCP     : ok=20/20  loss=  0.0%  min=12.4ms avg=15.1ms max=89.3ms

verdict: NORMAL
gejala : tidak ada — target merespon normal
```

Verdict otomatis: `NORMAL` / `TERDEGRADASI` / `MENCURIGAKAN` / `BERMASALAH`.

---

## Persyaratan

- Python 3.6+
- Linux untuk mode `monitor` (raw socket `AF_PACKET`)
- Root/`sudo` untuk `monitor` dan opsi `--ping`

## Instalasi

Tidak perlu instalasi — satu file, langsung jalan:

```bash
git clone <repo-anda> && cd <repo-anda>
sudo python3 floodcheck.py monitor
```

## Batasan Penting

- **Tidak ada tools yang bisa melihat trafik IP orang lain dari luar.** Mode `probe` hanya mengukur *gejala* (latensi/loss); loss tinggi konsisten dengan flood, tapi bisa juga berarti target down, link rusak, atau rate-limit. Pastikan dari 2+ vantage point.
- Mode `monitor` akurat hanya untuk trafik yang lewat interface mesin tempat dia jalan (atau segmen yang di-mirror ke situ).
- Ini bukan IDS pengganti — untuk produksi, pertimbangkan `tcpdump`/`suricata`/flow log router.

## Lisensi & Disclaimer

Gunakan hanya pada infrastruktur milik sendiri atau target dengan izin tertulis. Penulis tidak bertanggung jawab atas penyalahgunaan.
