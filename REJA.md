# ThreatChain — to'liq ishlaydigan platformaga o'tish rejasi

Bu reja DefectDojo / SecObserve / Wiz / Trivy / Gixy bilan solishtiruvdan kelib chiqqan.
Maqsad: mavjud kuchli tomonlarni (zanjir qoidalari, dalil halolligi, 0 bog'liqlik) yo'qotmagan
holda, yetishmayotgan qismlarni qo'shish va platformani haqiqiy serverlarda ishlatiladigan
darajaga olib chiqish.

**Boshlang'ich holat (2026-09-22 da o'lchangan):** 399 test o'tadi, `verify_platform.py` 5/5,
~9 900 satr kod, 23 modul, 0 ta Python bog'liqligi, 44 ta API marshruti.

---

## 0. Buzmaslik kafolati — har bir bosqichda amal qiladigan qoidalar

Foydalanuvchining asosiy sharti: **"bu qo'shishlar ishlashiga ta'sir qilmasligi lozim"**.
Shuning uchun quyidagi olti qoida butun reja davomida majburiy:

1. **Hisobot JSON'iga faqat qo'shiladi.** Mavjud kalit o'chirilmaydi va nomi o'zgartirilmaydi.
   Eski hisobotlar (yangi kalitsiz) UI'da va API'da avvalgidek ochilishi shart.
2. **Standart xulq o'zgarmaydi.** Har bir yangi imkoniyat yangi bayroq, yangi maydon yoki
   yangi bosqich sifatida kiradi. Bayroqsiz chaqirilgan `ci_gate.py`, `check_*.py` va API
   bugungidek ishlaydi.
3. **Har bir bosqich oxirida:** to'liq test to'plami + `verify_platform.py` + brauzerda
   jonli skan. Uchalasi o'tmasa, bosqich tugagan hisoblanmaydi.
4. **Dalil guard'i o'z kuchida qoladi** (`tests/evidence_guard.py`) — testlar hech qachon
   haqiqiy `*-runs/` hisobotlariga tegmaydi.
5. **Halollik qoidalari buzilmaydi:** umumiy xavfsizlik foizi yo'q; `verified: true` faqat
   tarmoqda kuzatilgan dalil uchun; qisman qamrov toza natija emas; sir qiymati ko'chirilmaydi.
6. **0 ta Python bog'liqligi saqlanadi.** Yangi funksiya uchun kutubxona kerak bo'lsa —
   yo standart kutubxona bilan yoziladi, yo tashqi CLI vosita sifatida `.tools/` ga o'rnatiladi.

### DefectDojo kodidan foydalanish
DefectDojo **BSD-3-Clause** litsenziyasi ostida. Litsenziya nusxa ko'chirishga ruxsat beradi,
lekin mualliflik xabarini saqlashni talab qiladi. Chalkashlikni oldini olish uchun tanlov:

> **Kod ko'chirilmaydi — g'oya va model olinadi, manba ko'rsatiladi.**

Aniq nimasi olinadi (quyida bosqichlarda ishlatiladi):
- `hash_code` / `unique_id_from_tool` / `legacy` dedup algoritmlari modeli va har bir skaner
  uchun alohida maydon ro'yxati (`HASHCODE_FIELDS_PER_SCANNER`) g'oyasi;
- topilma holatlari modeli (active / verified / false positive / risk accepted / mitigated);
- SLA standartlari: Critical 7 kun, High 30, Medium 90, Low 120;
- Product → Engagement → Test → Finding ierarxiyasi (bizda: Loyiha → Skan → Topilma).

---

## Bosqichlar ketma-ketligi va bog'liqligi

```
B1 (fingerprint)  ──┬──> B2 (triage)      ──┐
                    ├──> B3 (baseline/CI)  ──┤
B4 (aktiv grafi + SX-002) ──────────────────┼──> B7 (yangi UI)  ──> B8 (yakuniy tekshiruv)
B5 (IaC + SBOM)   ──────────────────────────┤
B6 (haqiqiy serverlar) ─────────────────────┘
```

B1 — poydevor, u bo'lmasa B2 ham, B3 ham qurib bo'lmaydi. B7 (UI) oxirgidan oldin turadi,
chunki u B1–B6 bergan ma'lumotni ko'rsatadi.

---

## B0 — Regressiya to'ri ✅ BAJARILDI (2026-09-22)

**Maqsad:** bugungi xulqni "muzlatib" qo'yish, toki keyingi 8 bosqich uni sezdirmay
o'zgartirib yubormasin.

**Qadamlar**
1. `tests/test_report_shape.py` — beshta skanerning har biri uchun hozirgi hisobot JSON'ining
   kalit sxemasi (maydon nomlari va turlari) snapshot sifatida yoziladi. Kalit yo'qolsa yoki
   turi o'zgarsa — test yiqiladi.
2. `tests/fixtures/legacy/` — bugungi formatdagi 5 ta haqiqiy hisobot nusxasi (sir va shaxsiy
   ma'lumotsiz). Har bir bosqichdan keyin ular API va UI'da ochilishi tekshiriladi.
3. `tests/test_api_contract.py` — 44 ta marshrutning status kodi va javob turi.

**Bajarilgani:** `tests/make_legacy_fixtures.py` + `tests/freeze_report_shape.py` (yordamchi
skriptlar), `tests/fixtures/legacy/` (15 ta muzlatilgan hisobot), `tests/fixtures/shape-snapshot.json`,
`tests/test_report_shape.py` (14 test), `tests/test_api_contract.py` (19 test).
Testlar **399 → 432**. `verify_platform.py` 6/6.

**Rejadan farqi (yaxshi tomonga):**
- 5 emas, 15 ta namuna: har bosqichdan **eng eskisi, eng yangisi va topilmasi eng ko'pi**.
  Eng eskisi — keyingi kod "har doim bor" deb hisoblagan maydon aslida yo'qligini ko'rsatadigan namuna.
- Qo'shimcha to'rtinchi qatlam: **jonli skan shakli** (`LiveShapeTests`). Statik fayllarni
  solishtirish kod o'zgarishini tutmaydi — repository skaneri (tashqi vositasiz, millisekundlarda)
  har yurishda haqiqatan ishga tushiriladi va muzlatilgan shakl bilan solishtiriladi.
  Mutatsiya bilan tekshirildi: maydon nomi o'zgartirilganda test yiqildi.
- API testi hermetik: barcha `RUNS` papkalari vaqtinchalik nusxaga ulanadi, shuning uchun
  hech qanday skan boshlanmaydi va haqiqiy dalil papkalariga tegilmaydi. Shu bilan birga u
  "eski hisobotlar API orqali ochiladi" shartini ham bajaradi.

**Yo'l-yo'lakay topilgan va tuzatilgan nuqson (A22):** `/api/rules/validate` ga noto'g'ri YAML
yuborilganda `yaml.YAMLError` `except ValueError` dan o'tib ketib, so'rov javobsiz uzilardi.
Endi 400 va aniq xabar qaytadi.

---

## B1 — Barqaror topilma identifikatori (fingerprint) ✅ BAJARILDI (2026-09-23)

**Nega birinchi:** baseline ham, triage ham, dedup ham "bu topilma o'sha topilmami?" degan
savolga javob bera olishni talab qiladi. Hozir bu faqat Repository (`fingerprint`) va SCA'da bor.

**Qadamlar**
1. Yangi modul `zanjir/findings.py`:
   - `FIELDS_PER_TOOL` — har bir skaner uchun xesh maydonlari (DefectDojo'ning
     `HASHCODE_FIELDS_PER_SCANNER` modeli asosida, o'z skanerlarimizga moslab):
     | Skaner | Maydonlar |
     |---|---|
     | semgrep | `rule_id`, `path`, kontekst xeshi (qator matnining normallashtirilgani) |
     | gitleaks | `rule_id`, `path`, sir **xeshi** (qiymat emas) |
     | pmd | `rule_id`, `path`, `class`/`method` |
     | dependencies | `package`, `ecosystem`, `advisory_id` |
     | images | `package`, `version`, `advisory_id`, `image_digest` |
     | web | `rule_id`, `url_path`, `method` |
     | repository/chain | mavjud `fingerprint` o'zgarmaydi |
   - **Qator raqami xeshga kirmaydi** — kod yuqoriga-pastga surilganda ID o'zgarmasligi uchun.
     Buning o'rniga qatorning normallashtirilgan matni (bo'shliqlarsiz, 120 belgigacha) ishlatiladi.
   - `fingerprint(tool, finding) -> 24 belgili hex`.
2. Har bir skaner modulida topilmaga `fingerprint` maydoni **qo'shiladi** (hech nima o'chirilmaydi).
3. SARIF eksportida `partialFingerprints: {"threatchain/v1": ...}` hamma bosqichga tarqaladi
   (hozir faqat Repository'da bor) — GitHub/GitLab annotatsiyalari shu bilan barqaror bo'ladi.

**Bajarilgani:** `zanjir/findings.py` (yangi), `tests/test_findings.py` (26 test).
Fingerprint qo'shildi: `scanners.py` (semgrep/gitleaks/pmd), `advisories.py`, `images.py`,
`webscan.py`, `chain_secrets.py`; SARIF `partialFingerprints` barcha bosqichda.
Testlar **432 → 458**. `verify_platform.py` 5/5. Brauzer konsoli toza.

**Haqiqiy loyihada tasdiqlangan:**
- `chain-demo` ni ikki marta skan qilish — 6/6 fingerprint bir xil.
- Ikki faylning boshiga 10 qator qo'shildi: 6 topilmadan 5 tasining qatori surildi
  (7→17, 12→22, 3→13 …), **6/6 fingerprint o'zgarmadi**.
- Jonli pipeline: 12 topilmaning hammasida fingerprint bor, takrorlanish yo'q.
- SARIF: har bir bosqichda `partialFingerprints` mavjud.

**Rejadan uch farq, uchalasi ham ataylab:**
1. **Gitleaks sirining xeshi ishlatilmadi.** Sabab: gitleaks `--redact=100` bilan ishlaydi,
   ya'ni sir bizning kodimizga umuman yetib kelmaydi (`"Secret": "REDACTED"`) — xeshlash
   uchun narsa yo'q. Bu to'g'ri ham: eksport qilingan SARIF ichidagi sirning SHA-256'i
   taxminni tasdiqqa aylantiradi. O'rniga **ustun raqami + entropiya** ishlatiladi —
   ikkalasi sirdan kelib chiqadi, uni oshkor qilmaydi, qator surilganda o'zgarmaydi va
   bitta fayldagi bitta qoidaning ikki turli sirini ajratadi. Bir xil ustun va bir xil
   entropiyali ikki moslik to'qnashadi — bu qabul qilingan va hujjatda yozilgan.
2. **Image identitetida digest emas, ro'yxatdagi image ID.** Har qayta yig'ishda digest
   o'zgaradi — digestga asoslangan identitet har rebuild'da barcha triage qarorlarini
   yo'qotardi.
3. **Image identitetida versiya yo'q** (rejada bor edi) — kutubxonalar bilan bir xil qoida:
   agar yangilanish CVE'ni tuzatsa, topilma o'zi yo'qoladi; tuzatmasa, bu hamon o'sha
   muammo va qarori saqlanishi kerak.

**PMD uchun `class`/`method` o'rniga kontekst matni:** PMD JSON natijasida sinf/metod nomi yo'q
(faqat `rule`, `beginline`, `priority`), shuning uchun semgrep bilan bir xil yondashuv qo'llanildi.

**Ta'sir:** faqat yangi maydon qo'shildi; B0 qo'riqchilari (shakl + API shartnomasi + jonli skan)
hech qanday yo'qotish yoki tur o'zgarishi ko'rsatmadi.

---

## B2 — Topilma hayotiy sikli (triage) ✅ BAJARILDI (2026-09-23)

**Hozirgi holat:** `repo_store.review` (Repository) va `dependencies.review` bor, lekin ular
**hisobotga bog'langan** — yangi skan qilinsa qaror yo'qoladi. Kod, image va web'da umuman yo'q.

**Qadamlar**
1. Yangi modul `zanjir/triage.py` — qarorlar **loyiha + fingerprint** bo'yicha saqlanadi
   (`profiles/triage/<loyiha>.json`), ya'ni skanlar bo'ylab yashaydi:
   ```
   status: investigating | confirmed | false_positive | accepted_risk | fix_planned | fixed
   owner, note, updated_at, + o'zgarmas audit jurnali (review-events/)
   ```
2. **SLA:** har bir ochiq topilmaga og'irligiga qarab muddat (Critical 7 / High 30 / Medium 90 /
   Low 120 kun — DefectDojo standarti, sozlanadigan). Muddati o'tganlar alohida belgilanadi.
   SLA hech qachon "xavfsizlik foizi"ga aylanmaydi — faqat muddat.
3. **Mavjud review'lar yo'qolmaydi:** eski `reviews.json` fayllari o'qiladi va yangi formatga
   bir martalik, qaytariladigan migratsiya bilan ko'chiriladi (eski fayl `.migrated` bilan saqlanadi).
4. API: `POST /api/triage` (bitta topilma), `POST /api/triage/bulk` (ko'p topilma),
   `GET /api/triage/<loyiha>`.
5. Hisobotda topilma yoniga `triage` obyekti qo'shiladi (bo'lmasa `null`).

**Bajarilgani:** `zanjir/triage.py` (yangi), `migrate_triage.py` (yangi CLI),
`tests/test_triage.py` (32 test), `tests/isolation.py` (yangi yordamchi).
Ulandi: `scanners.py`, `dependencies.py`, `images.py`, `webscan.py`, `repo_store.py`,
`pipeline.py`, `app.py`. Testlar **458 → 491**. `verify_platform.py` 5/5.

**Haqiqiy tizimda tasdiqlangan:**
- `chain-demo` skani → API orqali `accepted_risk` qarori → **yangi skan** →
  qaror yangi hisobotda ham ko'rindi (`untriaged=5 suppressed=1`).
- Migratsiya: mavjud yagona eski review (`validation-osv-control`) ko'chirildi, takroran
  ishga tushirilganda 0 ta ko'chirdi, manba fayl o'zgarmadi.
- Pipeline hisobotida har bir bosqich va SX-001 zanjiri ham triage ko'rinishini oladi.

**Rejadan yetti farq:**
1. **Saqlash joyi:** `profiles/triage/<loyiha>/decisions.json` + `review-events/` — bitta fayl
   emas, loyihaga bitta papka. Audit jurnali holat faylidan ajratilgan bo'lishi uchun.
2. **Eski fayllar `.migrated` deb qayta nomlanmadi.** Ular butunlay tegilmay qoladi, yoniga
   `reviews.migrated.json` belgisi yoziladi. Sababi: qayta nomlash mavjud
   `/api/dependencies/reports/<id>/reviews` endpointini buzardi. Belgini o'chirish —
   migratsiyani qayta ishga tushirish; mavjud qaror hech qachon qayta yozilmaydi.
3. **Repository review'larining "manba o'zgarsa qaror kuchini yo'qotadi" qoidasi saqlandi.**
   Ko'chirilgan qaror `bound_to` (manba xeshi) bilan yoziladi va manba o'zgarsa
   `stale: true` bo'lib, yopilgan deb sanalmaydi. Mavjud kafolatni yumshatmaslik uchun.
4. **API `stage` va `report_id` talab qiladi.** Server topilma haqiqatan o'sha hisobotda
   borligini tekshiradi — xato terilgan fingerprint hech kim ko'rmaydigan qarorga emas,
   xatoga aylanadi.
5. **Kuzatuv daftari qo'shildi.** SLA muddati "birinchi ko'rilgan" sanasidan hisoblanadi,
   shuning uchun tugagan skan ko'rgan fingerprint'larni yozib boradi (`seen`).
   `first_seen` hech qachon oldinga surilmaydi; yiqilgan yoki bekor qilingan skan soatni
   boshlamaydi.
6. **Baholanmagan og'irlikka muddat berilmaydi.** `UNKNOWN` uchun SLA yo'q — o'ylab topilgan
   muddat yo'qidan yomonroq. Gitleaks topilmalarida og'irlik yo'q, shuning uchun ularda
   muddat ham yo'q; bu hisobotda ko'rinadi.
7. **Interfeys hali yo'q.** Triage API orqali ishlaydi; ekrani B7 da quriladi. Hozircha
   hisobotda `triage` va `triage_summary` maydonlari bor, UI ularni ko'rsatmaydi.

**Yo'l-yo'lakay topilgan nuqson (A23):** tugagan skan yangi joyga yoza boshlagani uchun
testlar birinchi yurishdayoq haqiqiy `profiles/triage/` ga 3 ta loyiha yozdi. Dalil
qo'riqchisi endi bu papkani ham kuzatadi va izolyatsiya bitta qatorga tushirildi
(`tests/isolation.py`).

---

## B3 — Baseline, dedup va ishlatib bo'ladigan CI gate ✅ BAJARILDI (2026-09-23)

**Muammo:** `ci_gate.py` hamma topilmani sanaydi. Mavjud loyihada u birinchi kundanoq qizil
bo'ladi va o'chirib qo'yiladi — ya'ni amalda ishlatilmaydi.

**Qadamlar**
1. Yangi modul `zanjir/baseline.py`:
   - `diff(before, after)` — fingerprint bo'yicha `new` / `gone` / `unchanged`;
   - `since_last_green(target, stage)` — oxirgi `completed` skanni avtomatik topadi;
   - `suppressed()` — `false_positive` va `accepted_risk` triage'li topilmalarni chiqarib tashlaydi.
2. `ci_gate.py` ga yangi bayroqlar (standart xulq o'zgarmaydi):
   - `--baseline <report-id|last-green>` — faqat yangi topilmalarni sanash;
   - `--fail-on new-critical|new-high|any` ;
   - `--respect-triage` — qabul qilingan xavf va noto'g'ri signalni sanamaslik.
3. Skanlar bo'ylab dedup: bir topilma ikki skaner tomonidan topilsa (masalan, Gitleaks va
   Semgrep bir sirni), ular **birlashtirilmaydi**, balki `duplicate_of` bilan bog'lanadi —
   dalil yo'qolmaydi, lekin ro'yxat shishmaydi.
4. UI'da har bir hisobot uchun "oldingi skanga nisbatan" ko'rsatkichi.

**Bajarilgani:** `zanjir/baseline.py` (yangi), `zanjir/ci_gate.py` va `ci_gate.py` kengaytirildi,
`GET /api/baseline/<bosqich>/<hisobot>` qo'shildi, besh ko'rinishga "oldingi skanga nisbatan"
qatori qo'shildi (`dist/app.js` dagi umumiy `fillBaseline`), `tests/test_baseline.py` (26 test).
Testlar **491 → 518**. `verify_platform.py` 5/5.

**Haqiqiy CI yurishlarida tasdiqlangan** (vaqtinchalik `gate-demo` loyihasi, keyin o'chirildi):

| Ssenariy | Natija |
|---|---|
| Bayroqsiz (eski xulq) | `chiqish 1` · 6/6 sanaldi — o'zgarmagan |
| `--allow 6` | `chiqish 0` |
| Asos yaratildi, keyin o'zgarishsiz `--baseline last-green --fail-on new` | `chiqish 0` · **0 yangi / jami 2** |
| Compose'ga xavfli yangi xizmat qo'shildi | `chiqish 1` · **1 yangi / jami 3** · `RP-007 · admin · yangi` |
| Asos topilmadi (partial skan) | `chiqish 2` · aniq xato, **jim o'tkazmadi** |
| `--allow 2` (3 ta topilma) | `chiqish 1` |
| `--allow 2 --respect-triage` (1 tasi `accepted_risk`) | `chiqish 0` · `triage bilan olib tashlandi: 1` |

**Rejadan olti farq:**
1. **`--fail-on new` ham qo'shildi** (rejada `new-critical|new-high|any` edi). Og'irlik
   filtri bo'lmagan "har qanday yangi topilma" — eng ko'p kerak bo'ladigan holat.
2. **Identifikatorsiz topilma doim sanaladi.** Uni asos bilan solishtirib bo'lmaydi,
   demak eski ekanini isbotlab bo'lmaydi; gate hech qachon o'tkazish tomonga taxmin
   qilmaydi. Natijada `why: identifikatorsiz` deb yoziladi.
3. **Asos faqat `completed` skan bo'la oladi.** `partial` skan nimaga yetmaganini
   isbotlamaydi, shuning uchun undan kam qamrovli asos "yangi" ro'yxatini soxtalashtirardi.
   Joriy skan asosdan kam qamragan bo'lsa — bu ham ogohlantirish sifatida chiqadi.
4. **UI uchun "asos yo'q" xato emas.** Birinchi skanning solishtiradigan asosi bo'lmasligi
   normal holat; `/api/baseline/...` bunda `200 {available:false, reason}` qaytaradi
   (sog'lom sahifa konsolida qizil satr paydo bo'lmasligi uchun). CI gate uchun esa u
   hamon qattiq to'xtash — `NoBaseline` alohida sinf.
5. **Dedup faqat kod bosqichi ichida.** Bitta fayl, bitta qatorda ikki xil skaner —
   masalan Gitleaks `stripe-access-token` va Semgrep `detected-stripe-api-key`
   `app/config.py:7` da. Gitleaks asosiy (u satr haqiqatan ma'lum formatdagi sir ekanini
   isbotlaydi), Semgrep unga `duplicate_of` bilan bog'lanadi. **Hech nima birlashtirilmaydi**
   — ikkala dalil ham qoladi. Lockfile'dagi CVE va image'dagi o'sha CVE bog'lanmaydi:
   ular ikki xil joyda tuzatiladi.
6. **Umumiy tekshiruv (assessment) uchun asos tanlovi bo'yicha topiladi** — nishon bo'yicha
   emas. Boshqa tanlov bilan bajarilgan skan adolatli asos emas.

**Ta'sir:** bayroqsiz chaqiruv aynan avvalgidek ishlaydi; buni alohida regressiya testi
qo'riqlaydi.

---

## B4 — Aktivlar grafi va SX-002 ✅ BAJARILDI (2026-09-23)

**Hozirgi holat:** `portfolio.py` da loyiha → bosqich → nishon bog'lami **allaqachon bor**
(`BUNDLED`, `profiles/portfolio/`). Lekin zanjir qoidalari undan foydalanmaydi.
Repository hisobotida har bir xizmatning `image` nomi ham bor. Ya'ni kerakli ma'lumot mavjud.

**Qadamlar**
1. `portfolio.py` ga xizmat ↔ image bog'lami: `stages.images` ro'yxatiga ixtiyoriy
   `service` maydoni qo'shiladi (`{"id": "pilot-crapi-identity", "service": "identity"}`).
   Berilmasa — Compose'dagi `image` nomi bilan avtomatik moslashtiriladi, moslik topilmasa
   **taxmin qilinmaydi**, "bog'lanmagan" deb ko'rsatiladi.
2. `zanjir/chain_secrets.py` → `zanjir/chains.py` (SX-001 o'zgarishsiz ko'chadi):
   - **SX-002 — Tashqi ochiq xizmatda ekspluatatsiya qilinayotgan CVE.**
     Shart: xizmat host portidan ochiq (RP-001 sharti) **VA** o'sha xizmatning image'ida
     CISA KEV ro'yxatidagi yoki CRITICAL CVE bor.
     Teg: CWE-1395 (A03) + CWE-668 (A01). `verified: false`.
     Dalil: image digest, paket, CVE, KEV sanasi, EPSS bali, port bog'lami.
   - **SX-003 — Ochiq xizmat + tuzatilgan versiyasi mavjud CVE + debug rejimi.**
     (RP-006 bilan kesishadi; faqat uchalasi birga bo'lganda chiqadi.)
3. `pipeline.py` — korrelyatsiya qadami `images` bosqichini ham hisobga oladi.
4. UI'da "Zanjir" bo'limi: SX-001/002/003 bitta ro'yxatda, har biri qaysi ikki bosqichdan
   kelganini ko'rsatadi.

**Nega bu eng qimmat:** aynan shu Wiz/Orca sotadigan "toxic combination", lekin Compose
darajasida. Raqobatchilarda bu yo'q.

**Bajarilgani:** `zanjir/chain_secrets.py` → `zanjir/chains.py` (SX-001 o'zgarmadi),
SX-002 va SX-003 qo'shildi; `images.py` ga KEV+EPSS boyitish; `portfolio.py` ga
`link_images()` / `repository_name()` / `image_services()`; `pipeline.py` ga
`correlate_stages()` va `chain_gaps`; `verify_platform.py` ga yangi qadam;
UI'da umumiy "Cross-skaner zanjirlari" bo'limi dalil jadvali bilan.
Testlar **518 → 540**. `verify_platform.py` 6/6.

**crAPI'dagi haqiqiy natija:** 9 ta image'ning **9 tasi ham** Compose xizmatiga avtomatik
bog'landi (`crapi/crapi-web:${VERSION:-latest}` ↔ `crapi/crapi-web@sha256:…`).
SX-002 **hech narsa chiqarmadi** — va bu to'g'ri javob: crAPI barcha portni `127.0.0.1` ga
bog'laydi, ya'ni tashqariga ochiq xizmat yo'q. Bu SX-001 ning crAPI'dagi holatiga o'xshaydi
(u yerda `build:` yo'qligi sababli chiqmaydi).

**Sun'iy namunada haqiqiy ma'lumot bilan tasdiqlandi** (`crapi/crapi-web` image'i ochiq
portda + DEBUG=true):

| | Natija |
|---|---|
| Repository qoidalari | RP-001, RP-005, RP-006 |
| Image bog'lanishi | `pilot-crapi-web` → `web` (image nomi bo'yicha) |
| SX-002 | 2 ta · `libcrypto3`/`libssl3 3.5.1-r0` · **CVE-2026-31789** · CRITICAL |
| SX-003 | 2 ta · o'sha CVE · tuzatilgan versiya **3.5.6-r0** mavjud |
| EPSS | 0.00243 (haqiqiy FIRST.org bahosi) |
| CISA KEV | tekshirildi — bu CVE ro'yxatda yo'q |
| Bo'shliqlar | `stage_missing` (kod tanlanmagan), `image_partial` (Trivy bazasi yangilanmagan) |

**Rejadan sakkiz farq:**
1. **Image hisobotiga KEV va EPSS qo'shildi.** Trivy og'irlikni beradi, lekin CVE amalda
   ekspluatatsiya qilinayotganini bilmaydi. Kutubxonalar skaneri 0.6 dan beri bu kontekstga
   ega edi, image skaneri esa yo'q — SX-002 savolini berishning imkoni yo'q edi.
   `known_exploited: null` — "tekshirilmagan" degani, **"ekspluatatsiya qilinmaydi" degani emas**.
2. **KEV olinmasa qoida to'xtamaydi, bo'shliq yoziladi.** Rejada "qoida ishlamaydi" deyilgan
   edi. Ammo KEV yo'qligini "ekspluatatsiya qilinadigan CVE yo'q" deb qabul qilish — aynan
   o'sha jim o'tish. Og'irlik bo'yicha yarim shart hamon ishlaydi, shuning uchun qoida
   CRITICAL bo'yicha ishlashda davom etadi va **nimani tekshira olmagani aytiladi**.
3. **Noaniq bog'lanish alohida bo'shliq.** Bitta image'ni bir nechta xizmat ishlatsa
   (`image_ambiguous`), qaysi biri ochiqligini image nomidan bilib bo'lmaydi — taxmin
   qilinmaydi, operatordan `service` ni ko'rsatish so'raladi. Bu "bog'lanmagan" dan boshqa
   muammo va boshqacha tuzatiladi.
4. **Qisman tugagan image hisoboti zanjir dalili sifatida qabul qilinadi.** U CVE'ni
   **o'tkazib yuborishi** mumkin, lekin o'ylab topa olmaydi — demak topilgan har bir zanjir
   haqiqiy. Nimani o'tkazib yuborgani `image_partial` bo'shlig'ida yoziladi. (Baseline uchun
   esa qisman skan hamon yaramaydi — u yerda xato yo'nalish teskari.)
5. **SX-003 SX-002 ni almashtirmaydi, unga bog'lanadi** (`escalates`). Ikkalasining tuzatilishi
   har xil (image'ni yangilash / ustiga debug'ni o'chirish), va alohida turgani uchun
   debug o'chirilsa aynan bitta topilma yo'qoladi — baseline'da identitet almashinuvi bo'lmaydi.
6. **Image identifikatori Compose `${VERSION:-latest}` interpolyatsiyasini hisobga oladi.**
   Birinchi urinishda `crapi/crapi-web:${VERSION:-latest}` dan `crapi/crapi-web:${VERSION`
   chiqib, 9 tadan faqat 3 tasi bog'landi. Endi interpolyatsiya olib tashlanadi, registry
   `host:port` esa teg deb sanalmaydi.
7. **Umumiy tekshiruv loyihadagi boshqa image'larni ham ko'radi.** Image bosqichi bir yurishda
   bitta nishonni skanerlaydi; qolganlari uchun loyiha guruhidagi eng oxirgi natija bergan
   hisobot ishlatiladi. Aks holda bitta image skanerlagan tekshiruv qolganlari haqida
   jim qolardi.
8. **`verify_platform.py` ga alohida qadam.** Compose tomoni haqiqiy (chain-demo fayli
   haqiqiy skaner bilan o'qiladi), image tomoni sun'iy — bu yerda korrelyatsiya
   tekshiriladi, Trivy emas.

---

## B5 — Qamrovni kengaytirish: IaC, Dockerfile, SBOM ✅ BAJARILDI (2026-09-23)

**Bo'shliq:** Dockerfile va Compose'ning o'zi IaC sifatida tekshirilmaydi; SBOM yo'q.

**Qadamlar**
1. **Yangi bosqich `iac`** — Trivy `config` rejimi (`trivy config <dir>`): Dockerfile, Compose,
   Kubernetes, Terraform. Trivy allaqachon o'rnatilgan, yangi bog'liqlik yo'q.
   - Yangi modul `zanjir/iac.py`, yangi API `/api/iac/*`, `pipeline` da 6-bosqich.
   - Standart holatda **tanlanmagan** — mavjud jarayonlar o'zgarmaydi.
2. **SBOM eksporti** — `trivy image --format cyclonedx` orqali har bir image uchun CycloneDX
   1.6; loyiha darajasida birlashtirilgan SBOM. `GET /api/images/reports/<id>/sbom`.
   A03 (Software Supply Chain Failures) uchun tabiiy dalil.
3. **Nginx chuqurligi (ixtiyoriy, oxirida):** Gixy darajasiga chiqish maqsad emas. Ammo
   bizning proxy-ishonch qoidalarimizga yaqin 3 ta bo'shliq qo'shiladi:
   RP-009 `alias` traversal, RP-010 `resolver` orqali SSRF, RP-011 `add_header`
   qayta e'lon qilinganda xavfsizlik sarlavhalarining yo'qolishi.

**Bajarilgani:** `zanjir/iac.py` va `zanjir/sbom.py` (yangi), `dist/iac.js` (yangi ko'rinish),
RP-009/010/011 `repository.py` da, `tests/test_iac.py` (31 test).
Ulandi: `pipeline` (6-bosqich), `portfolio`, `baseline`, `triage`, `ci_gate`, `sarif_export`,
`app.py` (`/api/iac/*`, `/api/images/reports/<id>/sbom`, `/api/images/sbom?project=`),
`verify_platform.py` (yangi qadam).
Testlar **540 → 571**. `verify_platform.py` **7/7**.

**Haqiqiy natijalar:**

| Tekshiruv | Natija |
|---|---|
| IaC — `chain-demo` | 2 topilma: `DS-0002` (root foydalanuvchi, HIGH, CWE-250), `DS-0026` (HEALTHCHECK yo'q, LOW) |
| SBOM — `alpine:3.20` | CycloneDX 1.6, **14 komponent**, haqiqiy PURL va litsenziyalar |
| SBOM to'g'riligi | Trivy'ning **o'z** `--format cyclonedx` chiqishi bilan solishtirildi: **14 PURL'ning 14 tasi ham aynan mos**, hech narsa tushib qolmagan va hech narsa o'ylab topilmagan |
| Eski image hisoboti | SBOM o'rniga **409 va sabab** — bo'sh SBOM emas |
| RP-009 | `location /files` + `alias /var/www/data/` → CWE-22 / A01 (`/safe/` esa chiqmaydi) |
| RP-010 | `proxy_pass http://$http_x_upstream/v1` → CWE-918 / A01, `error` darajasi |
| RP-011 | `/api` blokidagi `add_header` server darajasidagi HSTS va CSP'ni bekor qiladi → CWE-693 / A06 |

**Rejadan yetti farq:**
1. **`iac_target` majburiy emas, ixtiyoriy maydon.** Uni `SELECTION_FIELDS` ga qo'shish uni
   majburiy qilardi (`validate()` kalitlar to'plamini aniq solishtiradi) va B5 dan oldin
   yozilgan har bir chaqiruv, shu jumladan brauzer, ishdan chiqardi.
2. **SBOM qayta skan qilmaydi.** `trivy image --format cyclonedx` image'ni ikkinchi marta
   yuklab olardi — o'n daqiqa va gigabayt. Trivy allaqachon `--list-all-pkgs` bilan
   ishlaydi, shuning uchun paket ro'yxati hisobotda saqlanadi va SBOM **topilmalar bilan
   bir xil dalildan** quriladi; ikkalasi hech qachon bir-biriga zid bo'lolmaydi.
3. **Paket ro'yxatidan maintainer va fayl ro'yxati olib tashlanadi.** Trivy ularni beradi,
   lekin maintainer elektron pochtasi eksport qilinadigan hisobotga tushmasligi kerak.
4. **Birlashtirilgan SBOM'da paketlar image'lar bo'ylab birlashtirilmaydi.** Ikki image'dagi
   bir xil kutubxona — ikki xil tuzatish joyi; ularni bitta komponentga yig'ish buni yashirardi.
   Paket ro'yxati yo'q image'lar `threatchain:skipped_images` da sanaladi.
5. **CycloneDX validatori yo'q** — loyihada Python bog'liqliklari yo'q va `jsonschema` ham,
   `cyclonedx-cli` ham mavjud emas. Shuning uchun 1.6 majburiy maydonlari testda to'g'ridan-to'g'ri
   tekshiriladi, **va SBOM Trivy'ning o'z CycloneDX chiqishi bilan solishtirib ko'rildi** — bu
   sxema validatoridan ko'ra kuchliroq tekshiruv, chunki u mazmunni ham qiyoslaydi.
6. **Trivy config Compose faylini tekshirmaydi** (uning qamrovi: Dockerfile, Kubernetes,
   Terraform, CloudFormation, Helm, ARM). Compose va Nginx uchun Repository bosqichi ishlaydi;
   bu ikkisi bir-birini takrorlamaydi.
7. **CWE xaritasi qisman va shunday deb aytiladi.** Trivy tekshiruvlarida CWE yo'q; xaritada
   bo'lmagan tekshiruv o'z ID si bilan ko'rsatiladi va hisobotda `untagged_checks` ro'yxati
   chiqadi. Namunada `DS-0026` aynan shunday.

**Ta'sir:** `iac` bosqichi standart holatda tanlanmagan; uni tanlamagan har qanday jarayon
avvalgidek ishlaydi va buni alohida test qo'riqlaydi.

---

## B6 — Haqiqiy serverlar bilan ishlash ✅ BAJARILDI (2026-09-25)

> B7 dan keyin bajarildi (foydalanuvchi so'rovi bilan tartib o'zgardi).

**Bu foydalanuvchining alohida talabi.** Hozirgi cheklovlar kodda aniq yozilgan:
image faqat `nom@sha256:digest` va faqat Docker Hub; manba faqat lokal papka; web faqat
ro'yxatga olingan URL.

**Qadamlar**
1. **Image — teg va shaxsiy registry.**
   - `nom:teg` qabul qilinadi, lekin **skandan oldin digest'ga aylantiriladi** va hisobotda
     ikkalasi ham yoziladi (teg ko'chib ketishi mumkin — digest o'zgarmas).
   - Shaxsiy registry: autentifikatsiya **faqat** muhit o'zgaruvchisi yoki mavjud
     `~/.docker/config.json` orqali. **Parol/token loyihada hech qachon saqlanmaydi**
     va hisobotga tushmaydi. UI'da faqat "registry'ga kirilgan / kirilmagan" holati.
2. **Manba — masofaviy git.** `https://` yoki `ssh://` repozitoriy faqat o'qish uchun
   `work/` ga klonlanadi (`--depth 1`), skandan keyin o'chiriladi. Commit SHA hisobotga yoziladi.
   Kirish ma'lumotlari saqlanmaydi (mavjud `git` credential helper ishlatiladi).
3. **Web — haqiqiy muhitlar.**
   - HTTPS majburiy emas, lekin TLS holati (versiya, sertifikat muddati, zanjir) qayd etiladi.
   - Autentifikatsiyali nishon: sarlavha muhit o'zgaruvchisidan olinadi
     (`THREATCHAIN_WEB_AUTH_<nishon>`), diskda saqlanmaydi, hisobotda maskalanadi.
   - Tezlik chegarasi (`--rate`), `robots.txt` ni hurmat qilish tanlovi, `User-Agent` aniq
     belgilanadi — skan qilinayotgan tomon kimligini bilsin.
   - **Ruxsat yozuvi majburiyligicha qoladi:** mas'ul ismi va sana bo'lmasa nishon
     ro'yxatga olinmaydi. Bu qoida yumshatilmaydi.
4. **Chegarani aniq aytish:** masofaviy Docker daemon, SSH orqali host skani va agent —
   bu rejaga kirmaydi va hujjatda shunday yoziladi.

**Bajarilgani:** `zanjir/remote_source.py` (yangi), `images.py` (teg + registry + auth),
`webscan.py` (TLS, auth, tezlik, User-Agent), `code_targets.register_remote()`,
`scanners.source_for()` / `check_target()`, `/api/registry/remote`,
"Nishon qo'shish" oynasiga 4-yorliq, `tests/test_remote_targets.py` (29 test),
`verify_platform.py` ga yangi qadam. Testlar **602 → 631**. `verify_platform.py` **8/8**.

**Jonli tasdiqlangan:**

| Tekshiruv | Natija |
|---|---|
| Masofaviy repozitoriy skani | `github.com/octocat/Hello-World` → `completed`, semgrep+gitleaks ishladi, commit `7fd1a60b…` yozildi |
| Klon tozalanishi | skandan keyin vaqtinchalik papka qolmadi (yiqilgan skanda ham) |
| Image teg | `alpine:3.20` → `docker.io/library/alpine:3.20`, `pinned: false`, `pin_note` bilan |
| Shaxsiy registry | `registry.example.com:5000/team/app:1.0` o'zgarishsiz uzatiladi |
| Registry paroli | `TRIVY_PASSWORD` ga uzatildi, metadata'da **yo'q** (mutatsiya bilan tekshirildi) |
| Web tokeni | `Authorization` sarlavhasiga tushdi, profil va hisobotda **yo'q** |
| Login'li URL | rad etildi, xato xabarida sir **chiqmadi** |
| TLS holati | protokol, shifr, subject, issuer, muddat va qolgan kun — baholanmaydi, faqat qayd etiladi |

**Rejadan sakkiz farq:**
1. **Teg digest'ga oldindan aylantirilmaydi.** Registry manifest API'siga alohida so'rov
   yuborish o'rniga Trivy'ning o'z natijasidagi `RepoDigests` o'qiladi: skan baribir
   registry bilan gaplashadi, ikkinchi marta so'rash esa yangi xato manbai bo'lardi.
   Hisobotda `reference_kind` va `resolved_digest` alohida yoziladi.
2. **Tegli skanda hajm keshi ishlatilmaydi.** Digest o'zgarmas, teg esa yo'q — shuning uchun
   `size_check: enforced_tag_not_pinned` va hajm har safar o'lchanadi. Tegdan keyin
   **yechilgan digest** keshga belgilanadi, tegning o'zi emas.
3. **Registry paroli har bir host uchun alohida.** `THREATCHAIN_REGISTRY_<HOST>_USERNAME/…PASSWORD` —
   bitta eksport qilingan parol image nomi ko'rsatgan **har qanday** registry'ga taklif
   qilinmasligi uchun. `DOCKER_CONFIG` standart holatda bo'sh papkaga qaraydi.
4. **Masofaviy URL'da login umuman qabul qilinmaydi.** `https://user:token@host/...` rad
   etiladi, chunki u loyiha profil fayliga yozilib qolardi. Yopiq repozitoriy uchun
   operatorning o'z git credential helper'i yoki SSH kaliti ishlatiladi.
5. **`ext::` va `file://` transportlari rad etiladi.** `ext::` git'ga ixtiyoriy buyruq
   bajartiradi; `file://` esa lokal yo'lni masofaviy ko'rinishida beradi — bu B7 auditida
   isbotlangan "ixtiyoriy yo'l" xavfining aynan o'zi.
6. **`target_root()` o'rniga `source_for()` kontekst menejeri.** Masofaviy nishonni
   tekshirish uchun klon kerak, lekin `pipeline.validate()` faqat tanlovni tekshiradi va
   tarmoqqa chiqmasligi kerak — shuning uchun `check_target()` alohida ajratildi.
7. **Web tezligi faqat sekinlashtiriladi.** `rate_delay` standart 0.5 s dan past bo'la
   olmaydi va 30 s dan oshmaydi: interfeys orqali skanni tezlashtirib yuborish mumkin emas.
8. **`robots.txt` ni hurmat qilish tanlovi qo'shilmadi.** Skaner ro'yxatdagi aniq yo'llarni
   oladi va umuman crawl qilmaydi; robots fayli bu yerda hech narsani o'zgartirmaydi.
   Buni qo'shish soxta ishonch berardi.

**Yo'l-yo'lakay tuzatilgan uch nuqson:** `User-Agent` da tipografik apostrof bor edi va
`http.client` sarlavhani latin-1 bilan kodlagani uchun **har bir so'rov** yuborilmasdan
yiqilardi; macOS'da `/var` symlink bo'lgani uchun klon yo'li `snapshot()` chegara
tekshiruvidan o'tmasdi; `scanners.targets()` masofaviy profilda `root` kalitini qidirib
`KeyError` berardi.

**Chegarada qoladi (ataylab):** masofaviy Docker daemon, SSH orqali host skani va agent.
Bular rejaga kirmagan va qo'shilmadi.

---

## B7 — Yangi veb interfeys: SIEM darajasidagi ish markazi ✅ BAJARILDI (2026-09-23)

**Talab:** "DefectDojo kabi, SIEM'ga o'xshatib, barcha funksiyalar uchun oynalar bo'lsin,
foydalanish juda oson bo'lsin."

**Muhim cheklov:** hozirgi UI — sof JavaScript, qurish bosqichisiz, CSP `script-src 'self';
style-src 'self'`. Shu saqlanadi: React/build kiritilmaydi, inline style yozilmaydi.

**Qadamlar**
1. **Yangi qobiq.** Chap menyu guruhlanadi:
   *Boshqaruv* (Boshlash, Loyihalar, Topilmalar, Zanjirlar) ·
   *Skanerlar* (Umumiy tekshiruv, Kod, CVE, Image, IaC, Sayt/API, Repository) ·
   *Tahlil* (Solishtirish, Trend, Eksport) · *Sozlamalar*.
   Yuqorida buyruq paneli: global qidiruv (`/` tugmasi), tez amallar, klaviatura yorliqlari.
2. **⭐ "Topilmalar" — yagona ekran (asosiy yangilik).**
   Barcha skanerlarning barcha topilmasi bitta jadvalda: og'irlik · skaner · loyiha · OWASP ·
   CWE · KEV · EPSS · triage holati · SLA muddati · birinchi ko'rilgan · oxirgi ko'rilgan.
   Filtrlar saqlanadi (URL'da), ko'p topilmani birdan triage qilish mumkin.
   **Aynan shu ekran platformani "SIEM"ga o'xshatadi** va bugun umuman yo'q.
3. **Topilma tafsiloti — yon panel.** Dalil (kod parchasi, HTTP javobi, paket zanjiri),
   zanjir bog'lanishi ("bu topilma SX-002 ning bir qismi"), triage formasi, qaror tarixi,
   tuzatish tavsiyasi.
4. **Har bir funksiya uchun oyna** — bugun faqat `.cmd` orqali bajariladigan ishlar UI'ga chiqadi:
   | Oyna | Bugun | Keyin |
   |---|---|---|
   | Loyiha ro'yxatga olish | `CHECK-PROJECT.cmd` | UI oynasi |
   | Image qo'shish (teg/digest/registry) | CLI | UI oynasi |
   | Web nishon + ruxsat yozuvi | `CHECK-WEB.cmd` | UI oynasi |
   | NVD kaliti | muhit o'zgaruvchisi | Sozlamalar oynasi |
   | Qoida muharriri | qisman bor | to'liq, tekshiruv bilan |
   | Hisobotlarni solishtirish | 2 skanerda | barcha bosqichda |
   | Eksport (SARIF/SBOM/MD/JSON) | havolalar | yagona eksport markazi |
5. **Loyiha sahifasi:** bosqichlar matritsasi, trend grafigi, ochiq zanjirlar, SLA holati,
   oxirgi skanlar — bitta ekranda.
6. **Qulaylik:** klaviatura navigatsiyasi, fokus ko'rinishi, kontrast, qorong'u rejim,
   telefon kengligida ishlash, har bir bo'sh ekranda "keyingi qadam" tugmasi.
7. **Halollik UI'da ham:** "tekshirilmagan" va "toza" hech qachon bir xil rangda bo'lmaydi;
   umumiy ball ko'rsatilmaydi; qisman qamrov har doim yozib qo'yiladi.

**Bajarilgani:** `zanjir/findings_index.py` va `zanjir/settings.py` (yangi backend),
`dist/shell.js`, `dist/findings.js`, `dist/project.js` (yangi ekranlar),
`dist/index.html` va `dist/style.css` qayta qurildi, `tests/test_workbench.py` (24 test).
Yangi API: `GET /api/findings`, `GET /api/findings/<id>`, `GET /api/settings`,
`POST /api/settings/nvd-key`, `POST /api/registry/{project,image,web}`.
Testlar **571 → 596**. `verify_platform.py` 7/7. Brauzer konsoli toza.

**Jonli tasdiqlangan:**

| Tekshiruv | Natija |
|---|---|
| Topilmalar jadvali | **8923 ta topilma** 7 bosqichdan bitta jadvalda, 189 ms |
| Fasetlar | og‘irlik, skaner, loyiha, OWASP, holat + 6 ta tez filtr |
| Qamrov banneri | "3 ta nishon hali tekshirilmagan" + katta hisobot qisqartirilgani |
| URL filtri | `#/findings?stage=code&severity=CRITICAL` — o‘qiladi va yoziladi |
| Yon panel | SLA ("7 kunlik muddat · 6 kun qoldi"), dalil jadvali, qaror formasi, tarix |
| Triage jadvaldan | API orqali saqlandi, kesh bekor qilindi, faset darhol yangilandi |
| Oynalar | Nishon qo‘shish (3 ta yorliq), Sozlamalar, Eksport markazi, Yorliqlar |
| Klaviatura | `g t`, `/`, `?`, `Esc` — hammasi ishladi |
| Qorong‘u rejim | butun interfeys bo‘ylab, tanlov eslab qolinadi |
| Telefon (375 px) | gorizontal siljish yo‘q, jadval 4 ustunga qisqaradi |

**Rejadan olti farq:**
1. **Loyiha ro‘yxatga olish oynasi standart holatda yozmaydi.** `repo_store.register_project()`
   fayl tizimi yo‘lini oladi va uning o‘z izohida "hech qachon brauzer API'si orqali ixtiyoriy
   yo‘l bilan" deb yozilgan — bu chegara ataylab qo‘yilgan: brauzerga ixtiyoriy yo‘l berish
   serverga butun diskni o‘qib, hisobotga solishga yo‘l ochadi. Oyna qurildi, lekin endpoint
   faqat `python3 app.py --allow-registration` bilan ishlaydi; aks holda `403` va **aynan
   ishlatiladigan CLI buyrug‘i** qaytadi. Image va web nishonlari uchun bunday chegara yo‘q —
   ular tekshiriladigan qiymat, fayl yo‘li emas.
2. **NVD kaliti saqlanadi, lekin hech qachon qaytarilmaydi.** `profiles/settings.json`,
   faqat egasi o‘qiy oladigan huquq (0600), javobda faqat oxirgi 4 belgi. Muhit
   o‘zgaruvchisi ustun turadi, va so‘rov tezligi kalit qo‘shilganda **serverni qayta ishga
   tushirmasdan** o‘zgaradi.
3. **Fasetlar har bir o‘lchov uchun alohida sanaladi.** Birinchi urinishda ular yakuniy
   natija ustida sanalardi va filtr nolga tushganda chip yo‘qolib, filtrni ortga qaytarib
   bo‘lmasdi. Endi har bir faset qolgan filtrlar ostida sanaladi va tanlangan qiymat
   0 bo‘lsa ham ko‘rinadi.
4. **DOM testlari o‘rniga sahifa shartnomasi testi + jonli brauzer tekshiruvi.** Loyihada
   Python bog‘liqliklari yo‘q, ya’ni DOM dvigateli ham yo‘q. Shuning uchun testlar
   inline `<script>`, `style="` va `.style.x =` yo‘qligini (CSP shartnomasi), har bir
   `data-view` uchun bo‘lim borligini, har bir `data-modal` uchun oyna borligini va jadval
   umumiy ball hisoblamasligini tekshiradi; ekranlarning o‘zi brauzerda yuritildi.
5. **Katta hisobot qisqartiriladi va buni aytadi.** Bitta image hisobotida 7424 topilma bor;
   jadval bitta hisobotdan 5000 tagacha o‘qiydi va nechtasi ko‘rsatilganini banner’da yozadi.
6. **Yon paneldagi bog‘liq topilmalar** `duplicate_of` va `escalates` orqali ko‘rsatiladi —
   B3 va B4 da qo‘yilgan bog‘lamlar endi interfeysda ko‘rinadi.

**Halollik interfeysda:** tekshirilmagan nishon sariq banner bilan alohida aytiladi;
baholanmagan og‘irlik chiziqli (hatched) chip bilan ko‘rsatiladi va jim kulrangga
aylanmaydi; qisman qamrovli skandan kelgan qator "Qisman qamrov" tegini oladi;
bo‘sh jadval "bu xavfsizlik xulosasi emas" deb yozadi; hech bir joyda umumiy ball yo‘q.

---

## B8 — Yakuniy tekshiruv va hujjatlar ✅ BAJARILDI (2026-09-25)

1. `verify_platform.py` kengaytiriladi: `iac`, SX-002, triage, baseline va masofaviy image
   qadamlari qo'shiladi.
2. To'liq regressiya: barcha testlar + brauzerda uchidan-uchiga skan + CI gate'ning to'rt xil
   bayroq kombinatsiyasi.
3. Hujjatlar: `README.md` (0.7 o'zgarishlari), `SCANNERS.md` (iac, SBOM, masofaviy nishonlar),
   `MUAMMOLAR.md` (yangi cheklovlar), `ci-examples/` (baseline bilan ishlaydigan namuna),
   va DefectDojo'dan olingan g'oyalar uchun manba ko'rsatilgan bo'lim.
4. Versiya `0.6.0` → `0.7.0`.

**Bajarilgani:**
- **Windows auditi:** B5–B7 modullari POSIX-ga xos yo'llar uchun tekshirildi va bitta haqiqiy
  nuqson topildi (A28): `remote_source.py` git'ga `core.hooksPath=/dev/null` berardi —
  Windows'da masofaviy skan **hech qachon ishlamasdi**. Tuzatildi; `tests/test_platform_paths.py`
  endi 8 ta yangi modulda `/dev/null`, `/tmp/`, `/etc/`, `/var/` qolmaganini doimiy tekshiradi.
- **C2 ning oxirgi qismi yopildi:** `pyproject.toml` dan aniq pinlangan (`==`) qatorlar
  o'qiladi. `flask==2.3.2` ni hal qilish uchun build vositasi kerak emas. Diapazon va
  `[tool.*]` jadvallari esa o'z sababi bilan bo'shliq bo'lib qoladi.
- **D2 yopildi:** NVD kaliti B7 dagi Sozlamalar oynasidan kiritiladi.
- **Versiya `0.7.0`** (`app.py`, `readiness.py`, `README.md`, `dist/index.html`).
- **MUAMMOLAR.md** qayta yozildi: A28 qo'shildi, eskirgan disk ma'lumoti yangilandi
  (3.2 GB → 17.0 GB, Colima to'xtatilgan), va "ataylab qoldirilgan chegaralar" jadvali
  qo'shildi — ular muammo emas, ongli qaror.

**Yakuniy holat:** testlar **639**, `verify_platform.py` **8/8**, brauzer konsoli toza.

---

## Hajm va tartib

| Bosqich | Mazmuni | Hajmi |
|---|---|---|
| B0 | Regressiya to'ri | kichik |
| B1 | Fingerprint | o'rta |
| B2 | Triage + SLA | o'rta |
| B3 | Baseline + CI gate | o'rta |
| B4 | Aktiv grafi + SX-002/003 | o'rta |
| B5 | IaC + SBOM + nginx | o'rta |
| B6 | Haqiqiy serverlar | katta |
| B7 | Yangi UI | eng katta |
| B8 | Yakuniy tekshiruv | kichik |

Har bir bosqich mustaqil tugaydi: uning oxirida platforma to'liq ishlaydigan holatda bo'ladi.
Ya'ni istalgan joyda to'xtash mumkin va hech narsa yarim qolmaydi.

## Xavflar va ularning oldini olish

| Xavf | Oldini olish |
|---|---|
| Fingerprint o'zgarishi eski triage qarorlarini uzadi | B1 da versiyalangan ID (`v1`), migratsiya jadvali |
| Yangi bosqichlar pipeline'ni sekinlashtiradi | `iac` standart holatda tanlanmagan; parallel bosqichlar ro'yxatiga qo'shilmaydi |
| Masofaviy nishonlarda maxfiy ma'lumot sizib chiqishi | maxsus guard testi: hisobot va log'da token qatori bo'lmasligi |
| UI qayta yozilganda eski hisobotlar ochilmay qolishi | B0 dagi `fixtures/legacy` har bir bosqichda tekshiriladi |
| Reja davomida "halollik" qoidalari yumshab ketishi | har bir bosqich mezonida alohida band |
