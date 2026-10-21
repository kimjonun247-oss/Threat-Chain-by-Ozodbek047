# ThreatChain — beta tayyorligi (2026-10-21)

Bu hujjat [PLAN.md](PLAN.md) bandlariga **dalil** beradi: har bandga qaysi kod, qaysi
test va qaysi o'lchangan raqam javob beradi. Legenda:

- **✅ (lokal)** — qabul mezoni lokal sintetik test bilan o'lchab bajarilgan.
- **TEKSHIRILMAGAN (serverda)** — mantiq va test tayyor, lekin haqiqiy vosita/haqiqiy
  miqyos natijasi faqat kuchliroq serverda olinadi (bu noutbukda disk/RAM yetmaydi).
- **⚠️** — qisman: logika bor, lekin bir qismi hali ochiq.

**O'lchov mashinasi:** Windows 11 Pro, 12 yadro, 7,3 GB RAM, ~1 GB bo'sh fizik xotira
skan paytida. Vositalar: Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0, Nuclei 3.11.1,
rasmiy 1 343 qoidali paket. PMD/CodeQL/Helm/Kustomize o'rnatilmagan (Java yo'q, disk kam).
Branch: `beta-readiness`. To'liq to'plam: **1133 test, OK (skipped=2)**, `python -m unittest
discover -s tests`.

---

## 1. Qisqa xulosa

Katta loyihada ThreatChain **yiqilmaydi va natijani yo'qotmaydi** — bu uchta eng xavfli
xato ([MUAMMOLAR.md](MUAMMOLAR.md) J1–J3) tuzatilgan va regressiya testlari bilan
qulflangan:

- Skan **har bo'lak natijasini darhol keshga yozadi**; uzilgan skan qolgan joyidan davom etadi.
- Vosita faqat **yangi ish ham, kesh ham bo'sh** bo'lsagina `failed`; aks holda kesh natijalari
  qoladi va holat `partial` (J3: oldin qayta skan 23 152 natijani yo'qotardi).
- Bir bo'lak vaqtga sig'masa, **ikkiga bo'linib qayta uriniladi** (4 marta), butun skan emas.

Qolgan cheklov — **tezlik va isbotlanmaganlik**, halokat emas: bu noutbukda birinchi skan
sekin (bo'sh RAM ~1 GB → bitta ishchi). Serverda ishchilar soni avtomatik oshadi (§4).

## 2. O'lchangan raqamlar (lokal)

### 2.1. Kod skani — rasmiy 1 343 qoidali paket bilan

| Korpus | Birinchi skan | O'zgarishsiz qayta skan |
|---|---|---|
| Python stdlib, 2 305 fayl | 447 s | **30,6 s** — natija aynan bir xil (312 topilma) |
| To'liq `Lib`, 26 503 fayl | 2 soat 44 daqiqa, 2 034 topilma | (J3 tuzatilgandan keyin to'liq daraxtda qayta o'lchanmadi — ~3 soat, serverda) |

Birinchi skan bu mashinada ~10 daqiqa / 4 000 fayl: bo'sh RAM ~1 GB bo'lgani uchun bitta
ishchi ishlaydi. Server (ko'proq RAM) ishchilar sonini oshiradi — §4.

### 2.2. Topilmalar jadvali (board) — 120 000 topilma, 4 nishon

`python benchmarks/board_load.py` (sintetik, izolyatsiyalangan `THREATCHAIN_DATA_DIR`):

`python benchmarks/board_load.py` (facet ustunlariga indeks bilan — severity/stage/status/project):

| O'lchov | Natija |
|---|---|
| Sovuq qurish (noldan) | **8,8 s** |
| SQLite hajmi | 158 MB |
| Sahifa-1 so'rovi (median / max) | 445 ms / 454 ms |
| Chuqur sahifa (offset ≈ jami) | 832 ms / 841 ms |
| Severity filtri (40 097 mos) | 343 ms |
| Project filtri (30 000 mos) | **201 ms** |
| Kombinatsiya (matn+severity+project, 1 019 mos) | **219 ms** |
| OWASP filtri (A03, 29 973 mos) | 387 ms |
| Fingerprint bo'yicha tafsilot | **7 ms** |

Natija to'g'ri (120 000 mos). Facet indekslari **filtrlangan** so'rovni sezilarli tezlashtirdi
(kombinatsiya 494→219 ms, project 334→201 ms — indekssiz o'lchovga nisbatan). Filtrsiz sahifa-1
hamon to'liq saralashga bog'liq (`ORDER BY` ichidagi runtime "overdue" CASE indeksni to'sadi);
120k da qabul qilinadigan, milliondan oshsa saralashni qayta ko'rish kerak (§6, ochiq).

### 2.3. Birinchi skan vaqt bo'linishi (2.1)

Har kod skani `report['timing']` da vaqtni fazaga bo'ladi. Namuna (12 fayllik SAST
korpus, to'liq rasmiy 1 343 qoidali paket, `--full`):

| Faza | Vaqt | Nima |
|---|---|---|
| `files_s` | 0,19 s | manbani o'lchash va o'qish (fayl ro'yxati) |
| `rules_s` | 0,09 s | loyiha tillariga qoida filtri |
| `scan_s` | 15,38 s | vositalarni ishga tushirish (Semgrep/Gitleaks) |
| `other_s` | 17,78 s | vosita versiyasi, boshlang'ich qoida-paket tayyorlash, kesh, yakun |
| `total_s` | **33,44 s** | |

Xulosa: kichik loyihada **qat'iy startup narxi** (versiya tekshiruvi + 1 343 qoidani
tayyorlash) skanning o'zidan ko'p — bu narx bir marta to'lanadi va katta loyihada `scan_s`
ustun bo'ladi (amortizatsiya). Shu sabab birinchi skan 4 000 fayl uchun ~10 daqiqa, lekin
qayta skan 30 s (§2.1).

## 3. PLAN bandlariga dalil

| # | Band | Holat | Dalil |
|---|---|---|---|
| 2.1 | Birinchi skan profili | ✅ (lokal) | `scanners.execute` har skanda `report['timing']` yozadi: `files_s` (o'qish), `rules_s` (qoida filtri), `scan_s` (vosita), `other_s`, `total_s`. §2.3. Test: `test_scan_profile.py` |
| 2.1b | Ishchilar soni xotiraga qarab | ✅ (lokal) | `scanners.semgrep_jobs()`: `scale<=1`→2, kattaga yadro/2 (2–8), bo'sh_RAM//750MB bilan cheklanadi; `THREATCHAIN_SEMGREP_JOBS` (1–32). Test: `test_beta_scan.py::WorkerAndMemoryTests`, `test_load_findings.py::WorkerCountTests` |
| 2.1c | Keraksiz fayllarni chetlash | ✅ (lokal) | `scanners.looks_minified`/`semgrep_skip_reason`: vendor/build/minified Semgrep'dan chiqadi (Gitleaks baribir o'qiydi), sabab hisobotda. Test: `test_beta_scan.py::SkipTests` |
| 2.1d | Til bo'yicha qoidalar | ✅ (lokal) | `scanners.project_families`/`filtered_rules`: loyihada yo'q til qoidalari berilmaydi, topilmalar soni o'zgarmaydi. Test: `test_beta_scan.py::LanguageFilterTests` |
| 2.2 | Xotira himoyasi | ✅ (lokal) | `out_of_memory` (137/-9 Linux OOM, 0xC0000017 Windows), `fewer_jobs`; `THREATCHAIN_SEMGREP_MAX_MEMORY`. Test: `test_beta_scan.py::WorkerAndMemoryTests`, `OutOfMemoryScanTests`. Haqiqiy OOM — TEKSHIRILMAGAN (serverda) |
| 2.3 | Uzilish + davom (aynan bir xil) | ⚠️ / TEKSHIRILMAGAN (serverda) | Bo'lak/kesh davom mantig'i (J1–J3) va kesh-darajadagi testlar bor; 26 500 faylda kill→resume fingerprint-aynan-bir-xil — serverda (`benchmarks/` kill/resume eksperimenti) |
| 2.4 | 100 000+ topilmada baza | ✅ (lokal) | §2.2 raqamlari; `benchmarks/board_load.py`. Test: `test_load_findings.py::BoardStoreTests`, `BoardRestartTests`, `ChainVolumeTests`. Sekin so'rovga indeks — §6 (ochiq) |
| 3.1 | Ground-truth | TEKSHIRILMAGAN (serverda) | `benchmarks/ground_truth.py` + `.json` (klon+skan); mos-kelish mantig'i testlangan: `test_ground_truth.py` |
| 3.3 | Zanjir izohi + ishonch | ✅ (lokal) | `chains.assess()`: har zanjirga `why[]` + `confidence`. Test: `test_chain_confidence.py` (ijobiy + salbiy) |
| 3.4 | Prioritet tartibi | ✅ (lokal) | `findings_store.priority()`: severity birinchi; ichida reachable→prod→fixable. §5. Test: `test_priority.py` |
| 4.1 | "Skaner ishlamadi" ≠ "xavf yo'q" | ✅ (lokal) | `ci_gate.classify_stage`: hech bir faylni o'qiy olmagan skaner `incomplete`; vosita yo'q/timeout/buzilgan JSON → hisobot `completed` emas, gate exit 2. Test: `test_failure_is_not_clean.py` |
| 4.2 | Chegaraviy holatlar | ✅ (lokal) | Bo'sh loyiha, uzun/kirill yo'l, symlink, katta fayl, buzilgan lockfile, git'siz papka, CRLF/LF. Test: `test_edge_cases.py` |
| 5.1 | Veb-interfeys xavfsizligi | ✅ (lokal) | Auth, 127.0.0.1, CSRF (Origin/Sec-Fetch/DNS rebind), XSS (CSP + nosniff), path traversal. Test: `test_web_security.py` |
| 5.2 | Sirlar maskasi | ✅ (lokal) | Sir qiymati hisobot/SARIF/Markdown/panel/ma'lumotlar papkasida yo'q. `benchmarks/run.py::bench_secrets` (ko'p joy × ko'p qiymat) |

## 4. Tavsiya etilgan chegaralar (server sozlamalari)

| O'zgaruvchi | Standart | Tavsiya | Nima qiladi |
|---|---|---|---|
| `THREATCHAIN_SEMGREP_JOBS` | avtomatik | o'rnatilmasin | Ishchilar sonini majburlaydi (1–32). Avtomatik: `yadro/2`, bo'sh_RAM//750MB bilan cheklangan |
| `THREATCHAIN_SEMGREP_MAX_MEMORY` | yo'q | kam RAM'li mashinada o'rnating (MB) | Semgrep per-fayl xotira chegarasi; oshgan fayl butun skanni o'ldirmasdan o'sha faylning xatosi deb belgilanadi |
| `max_parallel_scans` | 1 | serverda 2–4 | Turli loyihalarning kod/CVE skanlari parallel (image/IaC/web bittadan qoladi) |
| `THREATCHAIN_FULL_SCAN` / `--full` | o'chiq | inkremental shubhada | Keshni chetlab, hamma faylni qayta skanerlaydi |
| `THREATCHAIN_NORMAL_PRIORITY` | o'chiq | faqat CI runner'da `1` | O'rnatilsa skanerlar past ustuvorlikda (nice/ionice) ishlamaydi |

Ishchi xotira taxmini: to'liq paket bilan **~750 MB/ishchi**, lokal 7 qoida bilan ~200 MB.
Ishchilar soni `min(8, yadro/2, bo'sh_RAM//750MB)` bilan cheklangan — ya'ni koddagi yuqori chegara
**8 ishchi** (yadrolar ko'p va RAM yetarli bo'lsa ham). Undan oshirish uchun `THREATCHAIN_SEMGREP_JOBS`
qo'lda beriladi (1–32).

## 5. Ustuvorlik tartibi (3.4)

Bir xil og'irlik ichida tartib — uchta ha/yo'q savol, eng muhimi birinchi (`findings_store.priority`):

1. **+4** — tashqaridan erishib bo'lmaydigan (zanjir yoki web topilmasi erishiladigan deb sanaladi).
2. **+2** — ishlab chiqarish kodida emas (test/hujjat/namuna/generatsiya/vendor).
3. **+1** — o'tiladigan tuzatilgan versiya yo'q (tuzatishsiz kutubxona/image CVE; kod topilmasi
   tuzatiladigan deb sanaladi — tuzatish kod o'zgarishi).

**Og'irlik baribir birinchi hal qiladi:** test faylidagi CRITICAL — ishlab chiqarish kodidagi
HIGH'dan yuqori, lekin ishlab chiqarish kodidagi har CRITICAL'dan past. Umumiy "risk ball" yo'q.

## 6. Ataylab qoldirilgan chegaralar va ochiq bandlar

**Ataylab (taxminga asoslanmaslik uchun):** `pom.xml`/`build.gradle` o'qilmaydi (versiya diapazoni
— build'ni bajarish kerak), Helm/Kustomize render qilinmaydi (manba ↔ workload bog'lanishi yo'q,
SX-001/004/006/007 Kubernetes'da ishlamaydi), Nuclei faqat 6 ko'rib chiqilgan GET shabloni, RBAC/ko'p
foydalanuvchi yo'q (lokal 127.0.0.1).

**Ochiq (server/kelajak):**
- Board: facet ustunlariga indeks qo'shildi (filtrlangan so'rov tez). Filtrsiz sahifa-1
  (~445 ms/120k) hamon `ORDER BY` saralashiga bog'liq — milliondan oshsa saralashni qayta ko'rish kerak.
- CodeQL, PMD/Apex (Java), haqiqiy OOM, 26k faylda kill→resume — serverda.
- Image/IaC/web bosqichlari bittadan (Trivy kesh qulfi, web so'rov qoidasi).
- Birinchi skanning qoida-yuklash/skan/fayl-ro'yxati bo'linishi (2.1) alohida profil sifatida
  yozilmagan.

## 7. Rollback

Bu ish `beta-readiness` shoxida; `main` ta'sirlanmagan. Orqaga qaytarish:

- Shox commitini bekor qilish: `git revert <commit>` (har commit mustaqil o'tadi) yoki shoxni
  tashlab, `main`ga qaytish.
- Ma'lumot formati: board `FORMAT=4`, scan-cache `VERSION=3` — eski formatli fayl o'qilmasa
  avtomatik o'chirilib qayta quriladi (`findings_store.persist`, `scan_cache`), ya'ni downgrade'da
  faqat kesh qayta quriladi, manba (JSON hisobotlar) buzilmaydi.
- Yangi muhit o'zgaruvchilari standart holatda xulqni o'zgartirmaydi (hammasi opt-in).

---

*Dalil buyruqlari va raqamlari: [PROGRESS.md](PROGRESS.md), [MUAMMOLAR.md](MUAMMOLAR.md) J bo'limi.*
