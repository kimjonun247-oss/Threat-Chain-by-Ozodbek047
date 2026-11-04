# ThreatChain — beta-tayyorgarlik rejasi (2026-10-13)

Manba: `MUAMMOLAR.md` (J bo'lim "Hali ochiq"), `README.md`, beta-test topshirig'i.
Holat ustuni: `—` boshlanmagan · `✅` qabul mezoni o'lchov bilan bajarilgan · `⚠️` qisman ·
`TEKSHIRILMAGAN` — o'lchab bo'lmadi (sababi yonida). Dalillar (buyruq + natija) `PROGRESS.md` da.

**Cheklov (2026-10-13, foydalanuvchi):** bu noutbukda disk kam (27 GB bo'sh) — katta yuklashlar
(Docker image, Helm/Kustomize, CodeQL, ground-truth repolar) **serverda** bajariladi. Ular uchun
skript/konfiguratsiya tayyorlanadi, mantiq lokal stub yoki mavjud ma'lumot bilan sinaladi, haqiqiy
vosita natijasi `TEKSHIRILMAGAN (serverda)` deb belgilanadi.

Har qadamdan keyin: unit testlar + `verify_platform.py` + `benchmarks/run.py`, commit, `PROGRESS.md`.

## P0 — beta to'xtatuvchi (katta loyihada natija noto'g'ri yoki yo'q bo'lishi mumkin)

| # | Ish | Qabul mezoni (o'lchanadigan) | Holat |
|---|---|---|---|
| 2.1 | Birinchi skan profili | Bir xil korpusda vaqt bo'linishi (qoida yuklash / skan / fayl ro'yxati / boshqa) raqam bilan yozilgan | ✅ (lokal) |
| 2.1b | Ishchilar soni xotiraga qarab | `semgrep_jobs` bo'sh RAM va sozlama bo'yicha; unit test bilan chegaralar tasdiqlangan | ✅ (lokal) |
| 2.1c | Keraksiz fayllarni chetlash | node_modules, build/dist, vendor, minified (`.min.js`, uzun qatorli), binar, generatsiya fayllari skanga kirmaydi; sintetik daraxtda test | ✅ (lokal) |
| 2.1d | Til bo'yicha qoidalar | Loyihada yo'q til qoidalari Semgrep'ga berilmaydi; vaqt farqi o'lchangan, topilmalar soni o'zgarmagan | ✅ (lokal) |
| 2.2 | Xotira himoyasi | Xotira tugaganda (OOM / exit) bo'lak bo'linib qayta urinadi, butun skan yiqilmaydi; chegara sozlanadi (`THREATCHAIN_SEMGREP_MAX_MEMORY`); test | ✅ (lokal); haqiqiy OOM TEKSHIRILMAGAN (serverda) |
| 2.3 | 26 500 faylda uzilish + davom | Skan o'rtasida jarayon o'ldiriladi; davom ettirilgan skan natijasi uzilishsiz skan bilan **aynan bir xil** (fingerprint to'plami) | ⚠️ TEKSHIRILMAGAN (serverda) |
| 4.1 | "Skaner ishlamadi" ≠ "xavf yo'q" | Vosita yo'q / timeout / buzilgan JSON / tarmoq yo'q holatlarida hisobot `failed`/`partial`, gate o'tkazmaydi; har biri uchun test | ✅ (lokal) |
| 5.1 | Veb-interfeys xavfsizligi | Auth, standart 127.0.0.1, CSRF, XSS, path traversal, Nuclei faqat ruxsat etilgan manzilga — har biri uchun test | ✅ (lokal) |
| 5.2 | Sirlar maskasi | Hisobot, log va SARIF'da sir qiymati yo'q; test | ✅ (lokal) |

## P1 — beta sifati

| # | Ish | Qabul mezoni | Holat |
|---|---|---|---|
| 2.4 | 100 000+ topilmada baza | Sahifalash, qidiruv, filtr p95 vaqti o'lchangan; sekin so'rovga indeks; oldin/keyin raqam | ✅ (lokal) |
| 2.5 | Inkremental to'g'riligi | O'zgarmagan → bir xil; 1 fayl o'zgardi → faqat u qayta skanlanadi (soni o'lchangan); o'chirilgan fayl topilmalari yopiladi | ✅ (lokal) |
| 3.1 | Ground-truth | Lokal korpusda precision/recall/FP `BENCHMARKS.md` da; ochiq zaif loyihalar uchun pinlangan skript tayyor (`TEKSHIRILMAGAN (serverda)`) | TEKSHIRILMAGAN (serverda) |
| 3.2 | Eng shovqinli 10 qoida | Real kodda (Python stdlib + node_modules) top-10 qoida, sabab, tuzatish; har tuzatishdan keyin `sast` recall 30/30 | ⚠️ MUAMMOLAR J6–J9 da shovqinli qoidalar toraytirilgan; top-10 tahlili yozilmagan |
| 3.3 | Zanjir izohi + ishonch | Har zanjirda `why` va `confidence`; har zanjir qoidasi uchun ijobiy va salbiy test | ✅ (lokal) |
| 3.4 | Prioritet tartibi | Prod / fix bor / erishuvchanlik hisobga olinadi; mantiq hujjatlangan; test | ✅ (lokal) |
| 4.2 | Chegaraviy holatlar | Bo'sh loyiha, uzun yo'l, kirill/o'zbek yo'l, symlink, katta fayl, buzilgan lockfile, git'siz papka, CRLF/LF — har biriga test | ✅ (lokal) |
| 4.3 | Versiyalar hisobotda | Har hisobotda skaner versiyalari va qoida paketi xeshi; test | ✅ (lokal: code/repository; images/iac/web CI) |
| 5.3 | O'z bog'liqliklari | ThreatChain o'zini skanerlaydi; topilganlar tuzatiladi yoki asoslanadi | — |

## P2 — platforma va kengaytirish

| # | Ish | Qabul mezoni | Holat |
|---|---|---|---|
| 6.1 | Linux Docker image | Versiyalar pinlangan Dockerfile; image ichida verify + benchmark buyrug'i tayyor. Yig'ish `TEKSHIRILMAGAN (serverda)`. macOS `TEKSHIRILMAGAN` | ⚠️ `Dockerfile` bor (vositalar SHA-256 bilan pinlangan; asos image `python:3.14-slim-bookworm` teg bilan, digest emas); yig'ish TEKSHIRILMAGAN (serverda) |
| 6.2 | Helm / Kustomize | `helm template` / `kustomize build` bilan render → mavjud Kubernetes/IaC skaneri; stub binar bilan test; haqiqiy vosita `TEKSHIRILMAGAN (serverda)` | — |
| 6.3 | CI namunasi | GitHub/GitLab namunalari SARIF yuklaydi; `--prod-only`, `--fixable-only` integratsion test bilan | ⚠️ `ci-examples/` SARIF yuklaydi, flag mantig'i testlarda; namunalar haqiqiy GitHub/GitLab'da ishga tushirilmagan |

## P3 — yakun

| # | Ish | Qabul mezoni | Holat |
|---|---|---|---|
| 7 | `BETA_READINESS.md` | O'lchangan raqamlar, cheklovlar, TEKSHIRILMAGAN ro'yxati, tavsiya etilgan chegaralar, rollback; har PLAN bandiga dalil | ✅ |
