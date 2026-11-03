# ThreatChain — beta-tayyorgarlik jurnali

Har yozuv: nima qilindi, buyruq, chiqqan raqam, keyingi qadam. Mashina: Windows 11 Pro, 12 yadro,
7,3 GB RAM, 27 GB bo'sh disk. Vositalar: Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0, Nuclei 3.11.1,
rasmiy 1 343 qoidali paket. PMD, CodeQL, Helm, Kustomize o'rnatilmagan. Branch: `beta-readiness`.

## 2026-10-13 — 1-bosqich: baza

| Tekshiruv | Buyruq | Natija |
|---|---|---|
| Unit testlar | `python -m unittest discover -s tests -q` | `Ran 1074 tests in 186.164s` — `OK (skipped=1)` |
| Platforma | `python verify_platform.py` | 9/9 OK, 6 daq 9 s (`validation-runs/platform-windows.json`) |
| Benchmarklar (oflayn) | `python benchmarks/run.py > fayl` | **8 o'tdi, 1 yiqildi, 2 SKIP** (apex — Java yo'q, deep — CodeQL yo'q). Yiqilgani: `fixes` — `UnicodeEncodeError: '→'` |

**Topilgan xato:** natija faylga yo'naltirilganda Windows stdout'i cp1252 bo'ladi; `fixes` natija satridagi
`→` belgisi o'tayotgan tekshiruvni FAIL'ga aylantirardi. Tuzatish: `benchmarks/run.py` da
`stream.reconfigure(errors='replace')`. Tekshiruv: `python benchmarks/run.py --only fixes > fayl` →
`PASS fixes: iac: 5 ... 41 → 36; compose: 13 ... 17 → 3`. Benchmark mezoni o'zgartirilmadi.

Commitlar: `8b49d3c` (oldingi raundlar ishi), `b0789b7` (benchmark stdout).

## 2026-10-21/22 — 2-bosqich: P0/P1 mantiq, 2.1, 4.3, 2.5, kod-ko'rik

| Ish | Dalil | Commit |
|---|---|---|
| Commit qilinmagan beta P0/P1 ishi ko'rib chiqildi va kiritildi; `test_ground_truth` import-tartibi xatosi tuzatildi | `discover` → 1133 OK | `f6406d8` |
| `board_load.py` benchmark (owasp shakli) tuzatildi | 120k: qurish 7,7 s, sahifa ~490 ms | `7eeefe7` |
| `BETA_READINESS.md` | havola qilingan 78 test qayta ishga tushirildi | `0752922` |
| 2.1 birinchi skan vaqt bo'linishi (`report['timing']`) | 12 fayl, rasmiy paket: files 0,19 / rules 0,09 / scan 15,38 / other 17,78 / jami 33,44 s | `b3717fb` |
| Kod-ko'rik (high): zanjir ishonchi ziddiyati, OOM gate, facet indekslari | filtrlangan so'rov 494→219 ms | `debff6b`, `88939a1` |
| 4.3 provenance, 2.5 inkremental (o'chirilgan fayl) | `discover` → 1139 OK | `e5299d7` |

## 2026-11-02/03 — 3-bosqich: kamchiliklar ko'rigi va tuzatishlar

Manba: ikki parallel tahlil (kod bo'lmagan bosqichlarning katta-loyiha xatolari; hujjat ↔ kod mosligi)
va commit qilinmagan 2026-10-26 audit ishi. Har topilma kodda tasdiqlandi, tuzatildi, regressiya testi
yozildi (ko'pchiligi eski kodda yiqilishi tekshirildi). Batafsil: [MUAMMOLAR.md](MUAMMOLAR.md) K bo'limi.

| Ish | Dalil | Commit |
|---|---|---|
| 2026-10-26 audit ishi kiritildi; **D3 formulasi qaytarildi** (Base ballga Environmental formula qo'llangan edi: e'lon qilingan 9.9 → 10.0) | FIRST v3.1 spec §7.1/§7.3 iqtibosi; 5 ta e'lon qilingan ball testda | `7e0b29f` |
| Hujjatlar kod bilan moslashtirildi | — | `4dc5ba8` |
| LP#1 NVD kesh kaliti API kalit bilan ustiga yozilardi (kalitsiz → `TypeError`, dependencies bosqichi `failed`) | 6 test; eski kodda 4 error + 2 fail | `3821e54` |
| LP#5/#6 bosqich abadiy `running`da qolishi; job worker to'liq hisobotni har 2 s da qayta o'qishi | 7 test; eski kodda 7/7 yiqiladi | `cb31b92` |
| LP#10 IaC: Trivy `--timeout`, o'tkazib yuborilganlar, 64 MB chegara | soxta Trivy bilan execute | `5181ed3` |
| LP#8 dependencies progress har advisoryda qayta yozish; qulf bosqichni yiqitishi | eski kodda 2/2 yiqiladi | `c419729` |
| LP#2 repository/K8s o'qilmagan kirishlar → `partial`, gate gap/incomplete | bundled namunalarda 0 bo'shliq | `efa7424` |
| LP#4 zanjir korrelyatsiyasi: kesish qurish paytida | 100×5000: 1 156 → 31,7 MB; 50×3000: 8,76 → 3,80 s; 25 seed'da aynan bir xil | `ef65efe` |
| LP#3 web: Nuclei so'rovlari zaxiralanadi, inventar faqat qolganini sarflaydi | 7 test (haqiqiy Collector) | `a819a89` |
| LP#7 tuzatish rejasi OSV qayta tekshiruvi ommaviy | 2 000 paket: ≤3 chaqiruv (oldin ≤6 000); 20 seed'da aynan bir xil | `65618ef` |
| LP#12 chegaralar bosqichni yiqitmaydi, `*_limit` gap | 6 test | `84d3df2` |
| Diff uchun ikkinchi repo yurishi yo'q; O(F²)/O(W²) dedup; workload ID to'qnashuvi | korpusda eski yurish bilan aynan bir xil fayllar | `adadc0b` |
| F2 benchmark sir tekshiruvi aynan ekilgan qiymatlar bo'yicha | `benchmarks/run.py --only secrets` → PASS 11/11, 39 qiymat, sizish yo'q | `d6ab602` |

To'liq to'plam: `python -m unittest discover -s tests` → **1213 test, OK (skipped=2)** (255 s).

Oflayn benchmarklar (real vositalar): `python benchmarks/run.py` → **8 o'tdi, 0 yiqildi, 2 SKIP**
(apex — Java yo'q, deep — CodeQL yo'q), 324 s. SAST 30/30 (xavfsizda gate 0, signal 0), sirlar 11/11
(17 joyda 39 qiymat — sizish yo'q), IaC 41, Compose 11/11, tuzatishlar (iac 41→36, compose 17→3), web
(zaif saytda yetishmagan yo'q, 7 tasdiqlandi), impact (31 so'rov / 1 ulanish), gate chiqish kodlari kutilgandek.
2026-10-13 bazasi bilan solishtirganda: aniqlik o'zgarmagan, avvalgi `fixes` yiqilishi yo'q.

**Keyingi qadam:** shoxni push qilib CI'da uchala OS natijasini olish; serverda 2.3 (26k faylda
kill→resume), 3.1 ground-truth va CodeQL/PMD o'lchovlari.
