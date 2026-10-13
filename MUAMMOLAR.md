# Muammolar ro'yxati — 2026-09-17 to'liq sinovi

Loyihaning beshala bosqichi yakunlangach o'tkazilgan to'liq sinovda (271 test, 18 CLI skripti,
34 API endpoint, 9 web bo'limi, jonli crAPI laboratoriyasi) aniqlangan muammolar.

Holat: **A** — sinov davomida tuzatilgan, **B** — ochiq nuqson, **C** — ma'lum qamrov chegarasi,
**D** — muhit/operatsion.

---

## A. Sinov davomida tuzatilgan

Bularni qayta izlamaslik uchun yozib qo'yilgan.

| # | Muammo | Sabab | Tuzatish |
|---|---|---|---|
| A1 | `/api/assessments/reports/<id>/sarif` 404 qaytardi | Kod to'g'ri edi; server 14:20 da ishga tushgan, `app.py` 18:07 da tahrirlangan — eski jarayon eski marshrutni ushlab turgan | Server qayta ishga tushirildi (kod o'zgarmadi) |
| A2 | `check_all.py` ishlamay qolgan | 1-bosqichda `pipeline.validate()` ga `repository_target` qo'shilgan, skript yangilanmagan | `--repository-target` argumenti qo'shildi |
| A3 | `validate_pipeline.py` umuman ishga tushmasdi | `from zanjir.lab import listener` — modul `zanjir.httptest` ga qayta nomlangan, barcha testlar yangilangan, bu fayl unutilgan | Import tuzatildi |
| A4 | `validate_pipeline.py` payload'i rad etilardi | A2 bilan bir xil sabab — `repository_target` yo'q | Payload'ga maydon qo'shildi |
| A5 | `verify_pilot_api.py` `readiness` tekshiruvi yiqilardi | 0.6 da offline rejim olib tashlanganda rejim nomi `local_single_user_pilot` → `online_evidence_based_pilot` ga o'zgargan; skript eski qiymatda qolgan | Yangi qiymatga o'tkazildi |
| A6 | `verify_pilot_api.py` `health` tekshiruvi yiqilardi | Versiya `0.5.0` deb qattiq yozilgan, ilova `0.6.0` qaytaradi | Qattiq yozilgan versiya o'rniga `/api/health` va `readiness` mosligi tekshiriladi — yana eskirmaydi |
| A7 | Portfelda crAPI kod bosqichi "10 nishon" deb ko'rsatilardi | `BUNDLED` guruh `normalise()` dan o'tmagan, satr `len()` bilan sanalgan | `projects()` da normallashtiriladi |
| A8 | `crapi-full` portfelda ikki marta chiqardi | `derived()` faqat guruh kalitlarini chetlab o'tardi, guruh ichidagi nishon ID'larini emas | `claimed()` qo'shildi |
| A9 | Trend diagrammasi ko'rinmasdi | CSP `style-src 'self'` inline `style="width:…"` ni bloklaydi | CSP bo'shatilmadi; kenglik CSS sinflari orqali beriladi |
| A10 | TLS nazorat testi yiqilardi | Sertifikatlarda `SubjectKeyIdentifier`/`AuthorityKeyIdentifier` yo'q, OpenSSL 3.2+ talab qiladi | Ikkala kengaytma qo'shildi |
| A11 | TLS blokida mazmun kelgach ham `.empty` sinfi qolardi | `render()` `className` ni tozalamasdi | Tozalanadigan qilindi |
| A12 | Portfelda crAPI Repository bosqichi birdan "Tekshirilmagan" bo'lib qoldi | **Men yozgan test ishlab chiqarish ma'lumotlariga yozgan**: `test_chain_demo_sample.py` har safar `repo_store.scan_profile()` ni chaqirib `repository-runs/` ga haqiqiy hisobot yozardi; 57 ta test artefakti to'planib, 30 qatorlik ro'yxat oynasidan crAPI'ning haqiqiy dalillarini siqib chiqargan | Test `REPO_RUNS` ni vaqtinchalik papkaga yo'naltiradigan qilindi; 57 ta artefakt o'chirildi, 27 ta crAPI dalili saqlandi. To'liq to'plam endi hisobot papkalariga umuman yozmaydi |
| A14 | Yiqilgan image tekshiruvi hisobotida `message: null` qolardi | Tashqi 11 daqiqalik chegara `TimeoutError` beradi, lekin izoh faqat `ValueError` uchun yozilardi — operator hech qanday sababsiz "failed" ko'rardi. `crapi-identity` da aynan shu holat yuz berdi | Har bir yiqilish yo'liga o'qiladigan sabab berildi: chegara o'z matnini tushuntiradi va qayta urinishni taklif qiladi; kutilmagan tur uchun ham umumiy izoh yoziladi |
| A15 | Qoida paketini `--force` bilan qayta o'rnatish yiqilsa, qoidalarsiz holat qolardi | `install()` eski paketni tekshirishdan **oldin** o'chirardi; manifest'siz qoida fayllari esa "o'rnatilmagan" deb o'qilib, skan jimgina 7 ta lokal qoidaga tushardi | Yangi paket yonma-yon quriladi va faqat to'liq bo'lgach almashtiriladi; manifest'siz qoida fayllari endi xato sifatida ko'rsatiladi |
| A16 | Birlashtirilgan qoida fayli har bir qoidani ikki marta yuklatardi | Fayl registr papkasi ichida edi; `--config <papka>` uni ham o'qirdi | Fayl papkadan tashqariga ko'chirildi; buni test qo'riqlaydi |
| A17 | Trivy Aqua'ga anonim foydalanish ma'lumotini yuborardi | Trivy standarti; loyihaning "faqat paket nomi va versiya chiqadi" siyosatiga zid | Har bir Trivy chaqiruviga `--disable-telemetry --skip-version-check` qo'shildi (Semgrep va Nuclei'da allaqachon bor edi) |
| A18 | Test to'plami har yurishda dalil papkasiga hisobot yozardi | Mening B2 testim CLI'ni haqiqatan ishga tushirgan — A12 bilan bir xil xato | Test germetik qilindi; butun to'plam uchun qo'riqchi qo'shildi (`test_aa_…`/`test_zz_…`): to'plam boshidagi va oxiridagi dalil papkalari solishtiriladi. Aniq bog'lanadigan 4 ta artefakt o'chirildi; qolgan 53 ta `validation-osv-control` hisoboti orasidan test artefaktlarini ishonchli ajratib bo'lmagani uchun **o'chirilmadi** |
| A19 | Toza nusxada Semgrep va Gitleaks'ni o'rnatib bo'lmasdi | `.tools/` git'da e'tiborsiz; `setup_all.py` faqat Trivy, Nuclei, qoida paketi va PMD'ni o'rnatardi. Bu mashinadagi macOS nusxalari qo'lda qo'yilgan edi | `setup_scanners.py`: Gitleaks — rasmiy reliz, SHA-256 checksums fayli bilan; Semgrep — pinlangan versiya, loyiha ichidagi venv. `setup_all.py` ning birinchi (majburiy) qadami |
| A20 | Sintetik nazorat hisobotlari umumiy ro'yxatning yarmidan ko'pini egallagan | `validate_pilot.py` har yurishda yangi juftlik yaratar, eskisi ro'yxatda qolardi | 56 ta hisobot **arxivlandi** (o'chirilmadi): `dependency-runs/_archive/`. `validate_pilot.py` endi eskirgan juftlikni o'zi arxivlaydi; dalil sifatida havola qilingan juftlik joyida qoladi |
| A21 | Portfel skanerlangan image'ni "tekshirilmagan" deb ko'rsatdi | Portfel UI ro'yxati bilan bir xil `history()` ni ishlatardi — u faqat oxirgi 30 ta hisobotni qaytaradi. 36 ta image hisobotidan keyin `crapi-workshop` skani oynadan tushib ketdi. Bu 4-bosqichdagi mening xatoim; ma'lumot ko'paygach yuzaga chiqdi | `history()` ga `limit` parametri; portfel barcha qatorlarni o'qiydi (indeks tufayli arzon). Regressiya testi qo'shildi |
| A23 | Testlar haqiqiy triage do'koniga yozdi | B2 da tugagan skan yangi joyga — `profiles/triage/` ga — yoza boshladi. Hisobot papkalarini patch qiladigan testlar bu do'kon haqida bilmasdi, va to'plamning birinchi yurishi u yerda 3 ta haqiqiy loyiha yaratdi. Bu A12/A18 bilan bir sinfdagi xato, uchinchi marta | Dalil qo'riqchisi (`tests/evidence_guard.py`) endi `profiles/triage` ni ham kuzatadi — qoida shu: **skan yozadigan har qanday papka ro'yxatda bo'lishi kerak**. Izolyatsiya bitta qatorga tushirildi (`tests/isolation.py`), skan bajaradigan 9 ta test sinfiga qo'shildi; iflos yozuvlar o'chirildi |
| A28 | Windows'da masofaviy repozitoriy skani hech qachon ishlamasdi | B6 da klon buyrug'iga `core.hooksPath=/dev/null` berilgan edi — bu yo'l Windows'da mavjud emas, ya'ni git birinchi bayroqdayoq yiqilardi. B8 dagi Windows auditida topildi; macOS'da yuritilgan testlar buni hech qachon ko'rsatmasdi | Bo'sh vaqtinchalik papka ishlatiladi (u klon bilan birga o'chiriladi). `tests/test_platform_paths.py` endi yangi 8 ta modulda POSIX-ga xos yo'l (`/dev/null`, `/tmp/`, `/etc/`, `/var/`) qolmaganini doimiy tekshiradi |
| A25 | Har bir web so'rovi yuborilmasdan yiqilardi | B6 da qo'shilgan `User-Agent` da tipografik apostrof (U+2019) bor edi; `http.client` sarlavha qiymatini latin-1 bilan kodlaydi va `UnicodeEncodeError` beradi. Ya'ni yangi User-Agent bilan **birorta so'rov ham** ketmasdi | Qiymat sof ASCII qilindi; test `USER_AGENT.encode('latin-1')` ni tekshiradi |
| A26 | macOS'da masofaviy repozitoriy skani doim yiqilardi | `/var` — `/private/var` ga symlink. Klon yo'li resolve qilinmagani uchun `snapshot()` ning "fayl manba ichida" tekshiruvi har safar "Manba yo'li loyiha chegarasidan chiqdi" deb yiqilardi | `remote_source.clone()` vaqtinchalik papkani `.resolve()` bilan qaytaradi |
| A27 | Masofaviy loyiha ro'yxatda `KeyError` berardi | `scanners.targets()` har bir profilda `root` kaliti borligini nazarda tutardi; masofaviy profilda u yo'q | Masofaviy profil uchun `available: true` (lokal papka yo'q — klon skan vaqtida olinadi) va `source`/`url`/`ref` maydonlari qaytariladi |
| A24 | Compose fayli o'rniga YAML bo'lmagan fayl ko'rsatilsa, brauzer javobsiz qolardi | **A22 ning takrori.** O'shanda faqat `custom_rules.py` tuzatilgan; `repository.py` dagi `parse_yaml()` da aynan o'sha naqsh qolib ketgan edi — `yaml.parse()` va `get_single_node()` o'ralmagan, `yaml.YAMLError` esa `ValueError` emas. B7 ni audit qilishda `/etc/hosts` ni compose sifatida ko'rsatib topildi | `parse_yaml()` butunlay o'ralди va xato qator raqami bilan qaytadi; `webscan.py` dagi template yuklash ham o'raldi. **Sinf darajasida test** qo'shildi: `zanjir/` ichidagi har bir `yaml.parse/safe_load` chaqiruvi yonida `yaml.YAMLError` ushlagichi borligi tekshiriladi, ya'ni yangi qo'shilgan qo'riqlanmagan chaqiruv testni yiqitadi |
| A22 | Qoida muharririda YAML xatosi yozilsa, brauzer javobsiz qolardi | `custom_rules.parse()` ning chuqurlik/alias tekshiruvi `yaml.parse()` ni `safe_load` dan **oldin** chaqiradi va o'rab olinmagan edi. `yaml.YAMLError` `ValueError` emas, shuning uchun `app.py` dagi `except ValueError` uni ushlamagan — so'rov ishlovchisi yiqilib, ulanish javobsiz yopilgan | Tekshiruv sikli ham `except yaml.YAMLError` ichiga olindi; endi 400 va aniq xabar qaytadi ("YAML o'qilmadi: …"). **B0 bosqichidagi yangi API shartnomasi testi topdi** |
| A13 | Image bosqichi "9/9 nishon tekshirilgan" deb ko'rsatardi | Yiqilgan skan ham "tekshirilgan" deb sanalardi — hisobot yozuvi bor, lekin natija yo'q | `scanned_targets` endi faqat `completed` bo'lganlarni sanaydi; `attempted_targets` va `incomplete_targets` alohida. Endi "7/9 nishon natija berdi · Tugamagan: chatbot, identity" |

---

## B. Nuqsonlar

> **2026-09-17 bartaraf etish sessiyasi:** B1–B7 ning hammasi, so'ng C1, C4 va D3 ham yopildi.
> Testlar 258 → **399**. C va D bo‘limlari ham yopildi; optimallashtirish rejasi bajarildi.

### ~~B1. Yordamchi skriptlar test bilan umuman qoplanmagan~~ ✅ TUZATILDI

`tests/test_cli_scripts.py` qo'shildi (13 ta test), `pipeline.SELECTION_FIELDS` konstantasi
kiritildi. Endi quyidagilar avtomatik ushlanadi:

- har bir skript import bo'lishi (A3 turidagi eskirgan import);
- `zanjir.*` importlari haqiqatan mavjud modulga ishora qilishi;
- `--help` ishlashi va ish bajarmasligi;
- pipeline payload'i `pipeline.validate()` talabiga **aynan** mos kelishi — bu A2/A4 ni
  paydo bo'lgan zahoti ushlaydi, chunki endi maydonlar ro'yxati bitta manbadan olinadi;
- har bir tanlov maydoni uchun CLI bayrog'i borligi;
- eskirgan versiya/rejim satri qattiq yozilmaganligi (A5/A6);
- stdout'ga faqat JSON chiqishi (B2);
- `/api/health` va `readiness` versiyasi mos kelishi.

### ~~B2. CLI stdout sof JSON emas~~ ✅ TUZATILDI

`check_dependencies.py`, `check_image.py`, `check_web.py`, `scan_code.py`, `ci_gate.py` —
odamga mo'ljallangan barcha satrlar `file=sys.stderr` ga o'tkazildi. Endi
`script > out.json` to'g'ridan-to'g'ri parse qilinadi. Shartnoma ikki test bilan
qo'riqlanadi: manba tahlili (har bir `print()` yo `file=` bilan, yo `json.dumps`) va
haqiqiy ishga tushirish natijasini parse qilish.

### ~~B6. Ishlab turgan server versiyasini bilishning yo'li yo'q~~ ✅ TUZATILDI

`/api/health` endi `code_fingerprint` (jarayon **yuklagan** kod xeshi) va `started_at`
qaytaradi; `/api/readiness` esa **diskdagi** joriy xeshni beradi. Ikkalasi farq qilsa,
boshqaruv panelida qizil ogohlantirish chiqadi:

> **Server eski kod bilan ishlayapti.** Diskdagi fayllar o'zgargan (… ≠ …).
> O'zgarishlar kuchga kirishi uchun serverni qayta ishga tushiring.

Amalda tekshirildi: fayl o'zgartirilganda xeshlar ajraldi va ogohlantirish ko'rindi.

### ~~B7. Beshta skript `--help` ni tanimay, haqiqiy ish bajarardi~~ ✅ TUZATILDI

**Bu sinov davomida yangi aniqlandi va avvalgi hisobotimdagi xatoni ham ochdi.**
`pilot_evidence.py`, `setup_nuclei.py`, `setup_tools.py`, `validate_pipeline.py`,
`validate_web.py` da `argparse` umuman yo'q edi — noma'lum argument e'tiborsiz qolar va
skript odatdagidek ishga tushardi. `validate_web.py --help` yordam o'rniga **to'liq
haqiqiy Nuclei skanini** ishga tushirardi.

Buning natijasida avvalgi "18/18 CLI kirish nuqtasi ishlaydi" degan xulosam noto'g'ri edi:
u skriptlar yordam ko'rsatganini emas, haqiqiy ish bajarib `0` qaytarganini o'lchagan.

Beshalasiga minimal `argparse` qo'shildi; endi `--help` ishlaydi va noma'lum bayroq rad
etiladi. `HelpTests` buni doimiy qo'riqlaydi.

---

### B1–B2, B6–B7 dan olingan saboq

To'rttala nuqson ham bitta sababdan: **asosiy kod va yordamchi skriptlar o'rtasida
avtomatik bog'lanish yo'q edi.** Endi bog'lanish bor — `SELECTION_FIELDS` konstantasi,
`code_fingerprint` taqqoslash va `tests/test_cli_scripts.py`.

---

## B-ochiq → yopildi

### ~~B3. Kod topilmalari jadvalida sahifalash yo'q~~ ✅ TUZATILDI

Kod jadvaliga CVE bo'limidagi naqsh ko'chirildi: sahifada 25 qator, **qidiruv** maydoni va
**daraja filtri** (`ERROR` / `WARNING` / `INFO` / darajasiz). Hisobot almashtirilganda sahifa
va filtr nolga qaytadi, xuddi shu hisobot qayta render bo'lganda esa saqlanadi.

Tekshirildi: crAPI'ning 144 topilmasi `1/6 sahifa` bo'lib chiqdi, `ERROR` filtri 18 taga,
"Dockerfile" qidiruvi 6 taga qisqartirdi.

### ~~B4. SX-001 zanjiri bundled namunada hech qachon ishlamaydi~~ ✅ TUZATILDI

`samples/chain-demo/` sun'iy namunasi qo'shildi va **bundled profil** sifatida ham
Repository, ham Manba kodi ro'yxatiga yozildi (`ALLOWED_PROFILES`,
`scanners.bundled_code_samples()`). Endi hech qanday qo'lda sozlashsiz:

- **Repository** bo'limida `chain-demo` → RP-001, RP-005, RP-006, RP-007, RP-008;
- **Umumiy tekshiruv**da ikkala bosqichga `chain-demo` → qo'shimcha **SX-001**
  (`CWE-798` + `CWE-668` → `A01` + `A07`, `verified: false`).

Namunadagi kalit **soxta** va bu `README.md`, fayl izohi hamda provenance'da aytilgan.
Tasdiqlandi: kalit hisobot, SARIF va Markdown eksportlarining hech birida yo'q —
`secret_value: "hidden"` saqlanadi.

`tests/test_chain_demo_sample.py` (15 test) namunaning o'zini qo'riqlaydi: `build:` yo'qolsa
yoki port loopback'ga o'tkazilsa, testlar yiqiladi — ya'ni loyihaning asosiy farqi jimgina
ko'rsatilmaydigan bo'lib qolmaydi.

### ~~B5. Portfel guruhlashi crAPI uchun kodda qattiq yozilgan~~ ✅ TUZATILDI

`portfolio.unknown_targets()` qo'shildi: guruh nomlagan, lekin hech bir ro'yxatda
yo'q nishonlar aniqlanadi va portfel jadvalida qizil izoh sifatida chiqadi
("Ro'yxatda yo'q nishon: …"). Ilgari bunday nishon jimgina e'tiborsiz qolar va guruh
o'zi da'vo qilganidan kamroq qamrab, sog'lomroq ko'rinardi.

Tasdiqlandi: `pilot-mongodb` ro'yxatdan chiqarilganda ogohlantirish chiqdi, qaytarilgach yo'qoldi.

## C. Qamrov chegaralari

### ~~C1. Kod bosqichi `partial`, sababi noaniq~~ ✅

Xatolar toifalarga ajratiladi, fayllari va bajariladigan harakat ko'rsatiladi. crAPI'dagi 36 ta
xatoning hammasi Helm (Go) shablonlari ekani aniqlandi. Bosqich baribir `partial` qoladi —
o'qilmagan fayl haqiqiy bo'shliq.

### ~~C2. CVE qamrovi cheklangan~~ ✅

**Beshta yangi ekotizim qo'shildi.** Faqat aniq versiya yozadigan lock formatlari o'qiladi:

| Format | Ekotizim |
|---|---|
| `Pipfile.lock`, `poetry.lock`, `uv.lock` | PyPI |
| `gradle.lockfile` | Maven |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Packagist |
| `Cargo.lock` | crates.io |

Sinovda: 14 paket → **124 haqiqiy OSV topilmasi**, 4 tasi P1.

**2026-09-25 (B8) da qo'shildi:** `pyproject.toml` dan **aniq pinlangan** (`==`) qatorlar
o'qiladi. `flask==2.3.2` ni hal qilish uchun hech qanday build vositasi kerak emas — u lock
fayldagidek aniq. Diapazon (`requests>=2.0`), versiyasiz nom va `[tool.*]` jadvallari esa
o'qilmaydi va har biri o'z sababi bilan bo'shliq sifatida ko'rsatiladi
(`python_pyproject_not_exact_pin`).

**Qasddan qo'shilmagani:** `pom.xml`, `build.gradle` — bularda versiya
diapazon yoki xossa bo'lishi mumkin va uni hal qilish uchun build vositasini ishga tushirish
kerak. Bu modul repository kodini hech qachon bajarmaydi, ya'ni versiyani **taxmin qilish**
kerak bo'lardi — taxmin qilingan versiya esa dalilga o'xshagan, lekin dalil bo'lmagan CVE
mosligini beradi. Ular endi aniq sabab bilan rad etiladi (`gradle_lockfile_missing`, `maven_lockfile_missing`),
ya'ni operator nima qilish kerakligini biladi: `./gradlew dependencies --write-locks`.

**Hal qilib bo'lmaydigan qismi:** `psycopg2-binary` (versiyasiz) va `chromadb>=0.6.1`
(diapazon) kabi satrlar. Manbaning o'zida aniq versiya yo'q — hech bir parser uni o'ylab
topa olmaydi. Bular bo'shliq bo'lib qoladi va shunday ko'rsatiladi.

### ~~C3. crAPI image qamrovi~~ ✅ 8/9

C6 tuzatilgandan keyin `identity` ham o'tdi. Qolgan bittasi — C6 ga qarang.

### ~~C4. Windows tomoni~~ ✅ tekshiruv bitta buyruqqa keltirildi

`verify_platform.py` har qanday OS da vositalarni, unit testlarni, haqiqiy kod skanini,
RP-001..008 + SX-001 zanjirini, haqiqiy Nuclei nazoratini va CI gate chiqish kodlarini
**haqiqatan ishga tushiradi** va natijani `validation-runs/platform-<os>.json` ga yozadi.
macOS'da to'liq o'tdi. Windows'da: `VERIFY-WINDOWS.cmd` (ikki marta bosish). GitHub'da:
`ci-examples/threatchain-self-test.yml` Windows/Ubuntu/macOS matritsasida.

**2026-09-25 (B8):** B5–B7 da qo'shilgan modullar Windows uchun alohida auditdan o'tkazildi va
bitta haqiqiy nuqson topildi — `remote_source.py` git'ga `core.hooksPath=/dev/null` berardi,
bu yo'l Windows'da mavjud emas va masofaviy skan u yerda **hech qachon ishlamasdi** (A28).
Endi bo'sh vaqtinchalik papka ishlatiladi. Yangi modullarda POSIX-ga xos yo'l qolmaganini
`tests/test_platform_paths.py` doimiy tekshiradi.

**Halol:** Windows natijasining o'zi hali yo'q — uni faqat Windows mashinasi bera oladi. Qolgan
ish endi bitta buyruq; A19 tufayli toza Windows nusxasida vositalar ham avtomatik o'rnatiladi.

### ~~C5. Apex qamralmaydi~~ ✅ PMD bilan qamrab olindi

OSS Semgrep Apex'ni parse qila olmaydi, lekin **PMD** (BSD, ochiq manba) Apex xavfsizlik
qoidalariga ega. `setup_pmd.py` (7.27.0, GitHub e'lon qilgan SHA-256) o'rnatadi; Java kerak.
Skan faqat loyihada `.cls`/`.trigger` bo'lsa PMD'ni ishga tushiradi. 10 ta qoidaning har biri
CWE → OWASP bilan bog'langan; hisobot matni qoidaga xos qat'iy yozuv (PMD o'z xabariga
koddagi nomlarni qo'yishi mumkin). `chain-demo` ga zaif Apex klassi qo'shildi: ApexOpenRedirect
(CWE-601), ApexSOQLInjection (CWE-89), ApexSharingViolations (CWE-284) topildi.

### ~~C6. Katta image'lar~~ ✅

- `identity` (597 s birinchi marta) → keyingi skan **4 s** (digest tasdiqlangan).
- 1 GB chegarasi olib tashlanmadi. Operator uni **bitta skan uchun ongli ravishda** oshira oladi:
  `check_image.py --target X --max-size 2GB` (eng ko'pi 4 GB). Hisobot buni o'zi aytadi
  (`size_limit`, `size_limit_raised`, `scope`). Vaqt byudjeti ham mutanosib o'sadi
  (10 daqiqa / GB) — standart 1 GB skan o'zgarmaydi.
- Yuqori chegarada tasdiqlangan digest standart chegarani **chetlab o'tolmaydi**: har bir digest
  uchun eng qat'iy isbotlangan chegara saqlanadi.
- Disk tekshiruvi: image + 1 GB joy bo'lmasa skan boshlanmaydi va sababini aytadi; 5 GB dan kam
  qolganda boshqaruv panelida ogohlantirish chiqadi.

---

## D. Muhit va operatsion

| # | Holat | Natija |
|---|---|---|
| ~~D1~~ | ~~Colima ishlab turibdi~~ ✅ | `colima stop` bajarildi; Docker ish vaqti to'xtatildi |
| ~~D2~~ | ~~NVD kaliti yo'q, sekin~~ ✅ | B7 da **Sozlamalar oynasi** qo'shildi: kalit brauzerdan kiritiladi, `profiles/settings.json` ga faqat egasi o'qiy oladigan huquq (0600) bilan yoziladi, javoblarda hech qachon to'liq ko'rsatilmaydi va so'rov tezligi serverni qayta ishga tushirmasdan o'zgaradi. Muhit o'zgaruvchisi ustun turadi. Kalitning o'zini men ololmayman — bu foydalanuvchi hisobi |
| ~~D3~~ | ~~Yagona o'rnatish buyrug'i~~ ✅ | `setup_all.py` |

---

## E. 2026-09-25 toza nusxa sinovi — topilgan va tuzatilgan

Toza nusxada vositalar o'rnatildi, server ishga tushirildi, barcha bosqichlar ataylab zaif
Flask ilovasi, eskirgan `alpine:3.10` image va ochiq `.env`/`backup.sql`/`.git/config`
beradigan lokal sayt ustida yuritildi, interfeys Playwright bilan (1400px va 390px) aylanib chiqildi.

| # | Muammo | Sabab | Tuzatish |
|---|---|---|---|
| E1 | CI gate `partial` skanni **o'tkazib yubordi** (exit 0) | Faqat `failed` exit 2 berardi; OSV ishlamasa CVE bosqichi `partial` bo'ladi va gate topilmasi yo'q deb o'tardi | `ci_gate.incomplete_stages()`; tugamagan bosqich → exit 2, eski xulq `--allow-partial` |
| E2 | Lock fayli yo'q loyihada umumiy skan doim `partial`, `--baseline last-green` hech qachon topilmasdi | `no_supported_packages` tugamagan deb sanalardi | `pipeline.FINISHED_STAGE_STATES`; portfelda "Manifest yo'q" deb alohida ko'rinadi |
| E3 | Rasmiy paketsiz kod skaneri SQLi, pickle, `yaml.load`, Flask debug'ni ko'rmasdi; birorta lokal qoida gate'ga ta'sir qilmasdi | 7 ta qoidaning hammasi `WARNING`, taint yo'q | 12 ta yangi qoida (5 taint `ERROR`); sinov ilovasida 1 → 9 topilma, loyiha kodida 0 noto'g'ri signal |
| E4 | Ochiq `.env` (faqat sirlar) va sarlavhasiz SQL dump topilmadi | Shablon ikkita mustaqil shartni birga talab qilardi | Shablonlar v2; `validate_web.py` nazorati (soft-404 bilan) o'tadi |
| E5 | `/api/rules/validate` internetsiz ~100 s qotardi, test 15 s da yiqilardi | `semgrep --validate` semgrep.dev'dan lint to'plami yuklaydi | Bo'sh papka skani orqali o'sha parser, internetsiz ~2 s |
| E6 | TLS tekshiruvchi proxy bor tarmoqda hech narsa o'rnatilmasdi | `certifi` doim `SSL_CERT_FILE` dan ustun edi; proxy doim chetlab o'tilardi | `zanjir/nettrust.py`: operator CA'si birinchi; `THREATCHAIN_USE_PROXY=1` ixtiyoriy |
| E7 | Toza nusxada 3 ta test yiqilardi | Mahalliy ro'yxat (`validation-osv-control`), semgrep.dev, buzilgan `cryptography` | Nishon qidiruvi stub qilindi; E5; `cryptography` ishlamasa test o'tkaziladi, `pilot_tls` o'qiladigan xato beradi |
| E8 | Web skan rad etilgan nishonda umumiy "tugamadi" yozardi | `ValueError` matni yo'qotilardi | Sabab hisobotga yoziladi (test bilan) |
| E9 | `check_dependencies.py`, `scan_code.py`, `check_all.py` toza nusxada tushunarsiz xato/traceback | Standart `crapi-full` manbasi omborda yo'q | Mavjud nishonlar taklif qilinadi, traceback o'rniga exit 2 |
| E10 | `yarn.lock`, `pnpm-lock.yaml` o'qilmasdi | "Qo'llanmaydi" ro'yxatida edi | Ikkala format (yarn v1/Berry, pnpm v5/v6/v9) o'qiladi; git/fayl/workspace — nomli bo'shliq |
| E11 | Portfelda bosqich ustunlari ekrandan chiqib ketardi; `crapi-full` ikki marta | `th{white-space:nowrap}`; takrorlanish | Satr sarlavhasi o'raladi; ro'yxat takrorsiz |
| E12 | "So'nggi tekshiruvlar" doim bo'sh | `#history` ni hech bir skript to'ldirmasdi | `/api/dashboard` dagi `recent` bilan to'ldiriladi, bosilganda bosqich ochiladi |
| E13 | 390px da loyiha kartasi gorizontal chiqib ketardi | Jadval qobiqsiz | `table-wrap` |
| E14 | EOL OS'li image'da bitta topilma "toza" ko'rinardi | EOSL faqat yopiq bo'limda edi | Image sahifasida aniq ogohlantirish |

**Ataylab qoldirildi:** `pom.xml`/`build.gradle` va `==` siz Python qatorlari (versiyani taxmin
qilish kerak bo'ladi); masofaviy git'ni ichki manzilga ro'yxatga olish (lokal bir foydalanuvchili
vosita, ichki GitLab ham qonuniy nishon); proxy standart holatda chetlab o'tiladi (ambient
proxy ma'lumotlari operator so'ramaguncha uzatilmaydi).

---

## F. 2026-09-25 har bir vositani alohida sinash — topilgan va tuzatilgan

Har bir skaner belgilangan to'plamda sinaldi: 30 ta ma'lum zaiflik (5 til) + xavfsiz fayllar,
10 ta haqiqiy formatdagi soxta sir, Apex, `python:3.9.0-alpine` (to'g'ridan-to'g'ri Trivy bilan
solishtirildi), Dockerfile/K8s/Terraform, har bir RP qoidasini ishga tushiradigan Compose, zaif va
tuzatilgan sayt, 9 ta mashhur loyihaning haqiqiy lockfile'i, masofaviy DVWA. Alpine `3.10` → `3.24`.

| # | Muammo | Tuzatish |
|---|---|---|
| F1 | Masofaviy git nishoni bilan umumiy tekshiruv, CVE bosqichi va CI gate `KeyError('root')` bilan yiqilardi; gate exit 1 ("to'xtatdi") qaytarardi | `check_target`/`source_for` hamma joyda; kutilmagan xato gate'da exit 2; server har qanday xatoda 500 JSON qaytaradi (ulanishni jim uzmaydi) |
| F2 | Image/web ID'ni qayta ro'yxatga olish ulanishni javobsiz uzardi; nishonni yangilash/o'chirish yo'q edi | 400 va aniq xabar; `replace: true` bilan yangilash; `POST /api/registry/remove` va oynada "Ro'yxatdan chiqarish" (hisobotlar saqlanadi) |
| F3 | Real loyihalarda gate doim exit 2: Semgrep o'qiy olmagan Dockerfile yoki saytdagi 500 sahifa "tugamagan" sanalardi | `classify_stage()`: qamrov bo'shlig'i (ko'rsatiladi, to'xtatmaydi) va tugamagan skan (exit 2) ajratildi |
| F4 | Ko'p hujjatli `pnpm-lock.yaml` o'qilmasdi (vite: 0/1414) | Barcha hujjatlar o'qiladi: 1304 paket + 110 lokal `file:` bo'shliq |
| F5 | 27 ta topilgan zaiflikdan faqat 16 tasi gate'ni to'xtatardi | Yuqori ta'sirli CWE + qoida muallifining MEDIUM/HIGH ishonchi; PMD xavfsizlik qoidalari; natija 24/30, xavfsiz fayllarda 0 |
| F6 | Crawler `/files/` → `/files` (404), papka ro'yxati topilmasdi | Oxirgi `/` saqlanadi; yangi `http-dir-listing` tekshiruvi (CWE-548) |
| F7 | `Server: web` "versiya oshkor" deb belgilanardi | `Server` sarlavhasi faqat versiya raqami bo'lsa |
| F8 | SARIF'da 5 ta bir xil nomli run, kategoriyasiz; lokal qoida xabari umumiy matn edi | Har run'da `automationDetails.id` va skaner nomi; lokal qoidalar o'z xabari bilan |
| F9 | OSV ishlamasa CVE sahifasi "0 zaiflik" ko'rsatardi | "Tugallanmadi · N ta paket tekshirilmadi" va qizil ogohlantirish |
| F10 | Cargo workspace crate'lari crates.io paketi deb sanalardi (ripgrep 11/63) | Registry manbasi bo'lmagan poetry/uv/Cargo yozuvlari — nomli bo'shliq |
| F11 | Gitleaks DB URL paroli va git tarixidagi sirni topmasdi | `connection-string-password` qoidasi (shablonlar istisno); `gitleaks git` bilan tarix, faqat yangi sirlar qo'shiladi (commit bilan) |
| F12 | SBOM'da zaifliklar yo'q edi | CycloneDX `vulnerabilities` (85/85, har biri komponentga bog'langan) |
| F13 | Qoida paketi faqat codeload orqali (bloklansa aniqlik 27/30 → 11/30) | Pinlangan commit git orqali zaxira yo'l bilan olinadi |
| F14 | Hisobot ochilganda tanlovda boshqa loyiha qolardi | `syncTarget()` barcha bo'limlarda |
| F15 | Bitta ma'lumotlar bazasi uchun 6 ta RP-005 | Bitta topilma, yetib boradigan barcha xizmatlar ro'yxati bilan |
| F16 | 200 javobdagi stack trace topilmasdi | Aniq shakllar (Python traceback, Java stek, PHP fatal) har qanday statusda |
| F17 | Semgrep va paket topmagan holatlar (PHP mysqli SQLi, lxml XXE, Java/Go servlet injeksiyalari, SSTI, prototype pollution) | 11 ta yangi lokal qoida (jami 29); benchmark 30/30, DVWA'da 12 ta PHP topilmasi — hammasi haqiqiy, `impossible.php` toza |
| F18 | Faqat image/web nishoni bor loyiha portfelda yo'q edi | "Yakka nishon" loyihasi sifatida ko'rinadi |
| F19 | Kod va Compose bir xil ID'ni ishlata olmasdi; xabar "crapi nomi band" edi | Bir xil ID ruxsat; xabar haqiqiy sababni aytadi |

**Upstream chegaralar (vosita o'zida yo'q, qayd etildi):** PMD'ning ApexOpenRedirect/ApexCRUDViolation
sinov misolida ishlamadi; fayllararo XSS (DVWA `$html` keyinroq boshqa faylda chiqariladi) Semgrep OSS
taint tahlili doirasidan tashqarida; sayoz (depth 1) masofaviy klonda git tarixi faqat oxirgi commit.

---

## G. 2026-10-09 katta loyiha auditi — topilgan va tuzatilgan

Kod katta repozitoriy nuqtai nazaridan o'qib chiqildi; har band kichik proba bilan tasdiqlangan va
`tests/test_large_projects.py` da regressiya testiga ega. Bu mashinada `.tools/` o'rnatilmagan —
haqiqiy Semgrep/Trivy yurishi **bajarilmadi**.

| # | Muammo | Tuzatish |
|---|---|---|
| G1 | Bitta faylda bir xil matnli ikki qator (yoki bitta IaC faylidagi bir necha resurs) bitta identifikator olardi: ikkinchi zaif qator baseline uchun "yangi emas" edi, bitta triage qarori ikkalasini yopardi | `findings.separate()`: ikkinchi va keyingi takrorlar o'z tartib raqami bilan xeshlanadi. Birinchisi aynan avvalgidek — mavjud identifikatorlar o'zgarmaydi |
| G2 | RP-010 (`error`): `proxy_pass http://backend$request_uri` SSRF deb belgilanardi | Faqat manzilning host qismidagi mijoz o'zgaruvchisi sanaladi |
| G3 | RP-004 (`error`): `proxy_set_header Authorization $http_authorization` (oddiy uzatish) ishonch sarlavhasi edi | Faqat gateway o'zi hisoblagan qiymat (`$remote_user`, literal, boshqa nomdagi sarlavha) sanaladi; uzatish va bo'shatish — yo'q |
| G4 | RP-005 image nomidagi istalgan qism bo'yicha mos kelardi (`postgres-exporter`, `kafka-ui`, `chromatic`, `netcdf`); identifikator yetib boradigan xizmatlar ro'yxatiga bog'liq edi | Nom tokenlari bo'yicha, yordamchi vositalar istisno; identifikator faqat ma'lumotlar bazasining o'zi. **Bir martalik oqibat:** mavjud RP-005 topilmalari keyingi skanda yangi identifikator oladi |
| G5 | YAML anchor/merge (`<<: *defaults`) ishlatgan Compose fayli butunlay rad etilardi | O'qiladi; tugun soni chegarasi (30 000) va chuqurlik (50) alias bombasini to'xtatadi; takror kalit hamon xato |
| G6 | `build: .` bo'lgan xizmat uchun SX-001/004/006/007 hech qachon ishlamasdi | `chains.inside()` |
| G7 | Test fixture'dagi soxta sir ochiq xizmat bilan zanjirga ulanardi | Yangi `zanjir/pathclass.py`: har kod topilmasida `path_class`; zanjirlar faqat ishlab chiqarish kodiga quriladi, qolganlari `outside_shipped_code` bo'shlig'i sifatida sanaladi |
| G8 | Umumiy hisobotning Markdown eksporti SX-001 dan boshqa zanjir bo'lsa `KeyError` bilan yiqilardi | Barcha zanjirlar uchun bitta jadval |
| G9 | Foydalanuvchi loyihasidagi `profiles/`, `runs/`, `pilot/` papkalari jimgina skanerlanmasdi | Ilovaning o'z papkalari faqat ilova papkasining bevosita ichida o'tkazib yuboriladi (`engine.skip_directory`) |
| G10 | Lokal va rasmiy qoida bitta qatorda ikki topilma berardi | Bir vosita ichida ham, **CWE umumiy bo'lsa**, `duplicate_of` bilan bog'lanadi |
| G11 | Gate test/hujjat/namunadagi har bir mos kelishda to'xtardi | Ixtiyoriy `ci_gate.py --prod-only`; standart xulq o'zgarmagan |
| G12 | Faqat CVSS vektori bor advisory'lar (Go, RustSec, PyPA) `UNKNOWN` bo'lib gate'dan chiqib ketardi | CVSS v3.x bazaviy bali rasmiy formula bo'yicha hisoblanadi; `database_specific.severity` bo'lsa u ustun |
| G13 | Hajm chegarasi 10× ko'tarilgan, vaqt chegaralari esa 50 MB uchun yozilgan holicha qolgan | Vaqt chegarasi va Semgrep ishchilari soni snapshot hajmiga mutanosib (1–16×); 50 MB gacha hech narsa o'zgarmaydi |
| G14 | To'rtta lokal qoida ortiqcha signal berardi | `flask-debug` (`asyncio.run` istisno), `yaml-unsafe-load` (ruamel `YAML()` istisno), Python SQL/buyruq injeksiyasi (`int()`, `float()`, `shlex.quote()` sanitizer). **Semgrep bilan tekshirilmagan** — CI'dagi `sast` benchmarki tasdiqlashi kerak |

**Ochiq qolganlar** keyin o'lchandi va bir qismi tuzatildi — joriy ro'yxat H bo'limi oxirida.

---

## H. 2026-10-09 yuklama sinovi — o'lchangan, tuzatilgan, qolgan

Haqiqiy kod (Python `Lib`: 26 499 fayl, 260 MB, Semgrep 1.174, faqat 29 lokal qoida) va sun'iy
50 000 topilmali hisobotlar bilan o'lchandi. Mashina: Windows 11, 12 yadro, 7,3 GB RAM (~1 GB bo'sh).
Regressiya testlari: `tests/test_load_findings.py`.

**Sinalmagan:** rasmiy 1 300 qoidali paket, Gitleaks (tizimdagi 8.24.3 ≠ kutilgan 8.30.1), Trivy,
Nuclei, CodeQL, PMD, haqiqiy OSV tarmog'i, Linux.

| # | O'lchangan muammo | Tuzatish | Keyin |
|---|---|---|---|
| H1 | Hajm chegarasi faqat nusxalash paytida bilinardi; nusxalash paytida progress yo'q | `scanners.check_size()` oldindan sanaydi (nom+hajm, chegaraga yaqin bo'lsa 4 KB dan o'qib); har 500 faylda progress | Rad etishdan oldin 0 fayl nusxalanadi |
| H2 | Windows: manbadagi 214 belgili yo'l nusxada 309 bo'lib, butun skan `FileNotFoundError` bilan yiqilardi | Bunday fayl o'tkazib yuboriladi, sanaladi va nomi bilan ko'rsatiladi (`coverage.path_too_long`); o'qilmagan fayl ham skanni yiqitmaydi | Skan davom etadi |
| H3 | UTF-16 fayllar "binar" deb hech qachon skanerlanmasdi | Snapshot'ga UTF-8 qilib yoziladi (`transcoded_utf16`) | — |
| H4 | 50 000 natijani normallashtirish 41,5 s | Har fayl bir marta o'qiladi; yo'l tekshiruvi fayl bo'yicha eslab qolinadi | 13,8 s |
| H5 | Kod skanini bekor qilib bo'lmasdi | `scanners.cancel()`, `POST /api/scanners/cancel`; nusxalash paytida va vositalar orasida to'xtaydi (ishlab turgan vosita o'z vaqt chegarasida tugaydi) | holat `cancelled` |
| H6 | Mos kelmagan vosita versiyasi faqat "Tekshiruv tugallanmadi" derdi | `version_note`: o'rnatilgan va kutilgan versiya, o'rnatish buyrug'i | — |
| H7 | 7 GB mashinada 6 ta Semgrep ishchisi tizimni qotirardi | Ishchilar soni bo'sh xotiraga qarab cheklanadi (`engine.available_memory_mb`) | — |
| H8 | Holat so'rovi (`?status=1`) butun hisobotni o'qirdi: 2,06 s (46 MB) | Har hisobot yonida kichik `status.json`; quvur ham shuni o'qiydi | 0,07 s |
| H9 | O'ldirilgan skan abadiy `running` qolardi, manba nusxasi diskda qolardi | `zanjir/recovery.py`: server ishga tushganda egasi (pid) o'lgan hisobot `failed/Interrupted` qilinadi, `work-*` o'chiriladi | — |
| H10 | 8 ta bir vaqtdagi `/api/findings`: 102 s, server 1,1 GB (har biri jadvalni qayta qurardi) | Bitta quruvchi; hech narsa o'zgarmagan bo'lsa kesh 4 s dan keyin ham saqlanadi | 6,2 s, 499 MB |
| H11 | 200 topilmani birdan triage qilish: 110 s | `triage.decide_many()` — bitta o'qish, bitta yozish, har topilmaga o'z audit yozuvi | 3,5 s |
| H12 | 40 xizmat × 400 paket (1 200 noyob) rad etilardi; 2 001 manifest rad etilardi | Chegara **noyob** paket bo'yicha (50 000); nusxalar 500 000; manifestlar 20 000 | o'tadi |
| H13 | 4 000 zaif paketdan 2 500 tasi hisobotga tushmasdi (1 500 chegarasi) | Barcha advisory olinadi (chegara 50 000, 8 oqim, 24 soat kesh) | 0 tushib qolgan |
| H14 | 6/26 499 fayl o'qilmagani uchun skan `partial` → baseline va SX zanjirlari ishlamasdi | `baseline.gap_only()`: faqat qamrov bo'shlig'i bo'lgan `partial` skan asos bo'la oladi (ogohlantirish bilan) va zanjir unga tayana oladi. Vosita yiqilgan skan — hamon yo'q | — |
| H15 | `build: .` + 40 xizmat + 3 000 topilma = 60 000 zanjir (81 MB) | Har (qoida, xizmat) uchun 50 ta, eng jiddiylari, barqaror tartibda; qolgani `chain_limit` bo'shlig'i | 2 000 |
| H16 | Compose: 201 xizmat rad etilardi; port diapazoni topilma bermasdi; `include:` o'qilmasdi | 2 000 xizmat; `8000-8010:8000-8010` o'qiladi; `include:` fayllari o'qiladi (dalil o'sha faylga ishora qiladi); `build:` konteksti repo ildiziga keltiriladi | 1 001 xizmat: 7,7 s |
| H17 | `$REQ.GET` manbasi `Command.GET` ga mos kelib, Selenium'ning `self.execute(Command.GET, …)` ini SQL injeksiyasi derdi (gate'ni to'xtatgan 2 topilmadan 1 tasi) | Manba faqat lug'at sifatida o'qilganda: `.GET.get(...)`, `.GET[...]` | haqiqiy Semgrep bilan tekshirildi |

**Tuzatilmaganlar** keyin qurildi — I bo'limiga qarang; hali ochiq qolgani o'sha bo'lim oxirida.

---

## I. 2026-10-10 katta loyihalar uchun uchta arxitektura o'zgarishi

Regressiya testlari: `tests/test_architecture.py`, `tests/test_load_findings.py`. O'lchovlar o'sha
mashinada (Windows 11, 12 yadro, 7,3 GB RAM), Semgrep 1.174, faqat lokal qoidalar bilan.

### I1. Inkremental skan (`zanjir/scan_cache.py`)

O'lchov shuni ko'rsatdi: sekinlik nusxalashda emas, har faylni **birinchi marta ochishda** (93 fayl/s;
tizim keshidagi fayl — 1 000 fayl/s; hardlink bilan nusxalash orasidagi farq ahamiyatsiz). Shuning uchun
yechim — o'zgarmagan faylni umuman ochmaslik va qayta skanerlamaslik.

- Har loyiha uchun `scan-cache/<nishon>.sqlite3`: fayl → hajm, mtime, SHA-256; va (qoidalar+vosita
  versiyasi, vosita, fayl) → o'sha mazmun uchun topilmalar va o'qilmagan-fayl xatolari.
- Hajmi va mtime o'zgarmagan fayl ochilmaydi. Mazmuni avval skanerlangan fayl skanerga berilmaydi.
- Qoida fayli yoki vosita versiyasi o'zgarsa — hech narsa mos kelmaydi, hammasi qayta skanerlanadi
  (sinovda aynan shunday bo'ldi: qoidani tahrirlaganimdan keyin kesh o'zini bekor qildi).
- Har vosita o'z ehtiyoji bo'yicha: yiqilgan vosita (masalan, mos kelmagan Gitleaks) hamma faylni
  qayta so'raydi, lekin Semgrep'ni qayta ishlatmaydi.
- To'liq skan: `scan_code.py --full` yoki `THREATCHAIN_FULL_SCAN=1`. CodeQL yoqilgan bo'lsa manba
  har doim to'liq nusxalanadi (u fayllararo tahlil qiladi).
- Hisobotda `coverage.incremental`: nechta fayl skanerlandi, nechta oldingi skandan olindi.

**Chegarasi (git indeksi bilan bir xil):** mazmuni o'zgarib, hajmi va mtime o'zgarmagan fayl ko'rinmaydi.

| | Birinchi skan | O'zgarishsiz qayta skan | 1 fayl o'zgargan |
|---|---|---|---|
| stdlib (2 305 fayl) | 37 s | **7 s** | 14 s |
| To'liq `Lib` (26 503 fayl) | 664 s | **49 s** | — |

Inkremental natija to'liq skan natijasi bilan aynan bir xil (fingerprint'lar va snapshot xeshi) —
bu testda ham, haqiqiy kodda ham tekshirildi.

### I2. Topilmalar jadvali SQLite'da (`zanjir/findings_store.py`)

- Qatorlar diskdagi jadvalda; qidiruv, saralash, sahifalash va faset sonlari — SQL so'rovi.
- Har (bosqich, nishon) qaysi hisobotdan qurilganini eslaydi: yangi skan faqat o'sha nishon qatorlarini almashtiradi.
- Triage qarori qatorlarni joyida yangilaydi, hisobot qayta o'qilmaydi.
- Server jadvalni `findings-board/` da saqlaydi; qayta ishga tushganda faqat nima o'zgarganini tekshiradi.

| 150 000 qator | Oldin (xotirada) | Keyin |
|---|---|---|
| Server xotirasi | 499 MB (cho'qqi 1,1 GB) | **65 MB** |
| Filtrlangan qidiruv | 1,15 s | 0,6 s (matn bilan 1,1 s) |
| Topilma tafsiloti | 2,4 s | 0,01 s |
| 8 ta parallel so'rov | 102 s → 6,2 s (H10) | 6,3 s |
| Birinchi qurish | 10,8 s | **18–21 s (sekinroq)** |
| Server qayta ishga tushgandan keyin | 10,8 s | 2,0 s |

Birinchi qurish sekinroq — bu to'lov. U bir marta, bo'sh o'rnatmada to'lanadi; keyin faqat o'zgargan
nishon qayta quriladi (50 000 topilma uchun ~7 s).

### I3. Katta hisobotlar

- **Hisobot sahifasi:** 2 000 dan ko'p topilmali hisobot yonida `view.json` — eng jiddiy 2 000 tasi va
  haqiqiy son. Sahifa shuni oladi va `message` da nechta ko'rsatilganini aytadi.
  50 000 topilma: 55 MB / 3,9 s → **1,9 MB / 0,09 s**. Yuklab olish va eksport — hamon to'liq hisobot.
- **Sahifalash:** har qanday hisobot URL'ida `?offset=&limit=` (ko'pi bilan 1 000).
- **Umumiy hisobot** bosqich hisobotlarini nusxalamaydi, ID bilan ko'rsatadi; o'qilganda qayta yig'iladi
  (iste'molchilar uchun shakl o'zgarmagan). 54 MB → 1 KB dan kam. Eski hisobotlar avvalgidek ochiladi.
- **SARIF:** `ci_gate.py --sarif-max-results N` — eng jiddiylari qoladi, haqiqiy son run xossalarida.

### I4. Qolgan kamchiliklar

| Muammo | Tuzatish |
|---|---|
| Bekor qilish faqat vositalar orasida ishlardi | `run_tool()`: ishlab turgan vosita va uning bolalari o'ldiriladi; chiqish fayllarga yoziladi (xotiraga emas) |
| Bitta global qulf | `ScanSlots`: turli loyihalar `max_parallel_scans` gacha parallel (standart 1 — xulq o'zgarmagan); bitta loyiha ikki marta emas |
| Compose `extends` | Yechiladi (shu fayl va boshqa fayl), Compose birlashtirish qoidalari bilan; yechilmagani `unknowns` da |
| CodeQL qat'iy 2 GB / 2 oqim | Bo'sh xotiraning yarmi (2–16 GB), yadrolarning yarmi. **Sinalmagan** — CodeQL o'rnatilmagan |
| `eval("literal")`, `SET`/`PRAGMA` shovqini | Ikkala qoida toraytirildi; haqiqiy Semgrep bilan tekshirildi. To'liq daraxtda 502 → 468 topilma |

### I5. 2026-10-11 — qolgan ochiq bandlar

| Band | Nima qilindi |
|---|---|
| Interfeysda bekor qilish tugmasi | Kod ko'rinishida "Bekor qilish" tugmasi va server yuborayotgan jonli progress matni. `npm run all` (TypeScript strict + ESLint + build) va `npm run check` o'tdi; brauzerda sahifa xatosiz ochildi |
| Kubernetes | `zanjir/kubernetes.py`: manifest papkasi (yoki fayli) `compose` maydonida ko'rsatilsa, Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod, Service, Ingress va NetworkPolicy o'qiladi. Hisobot Compose hisoboti bilan bir xil shaklda, shuning uchun image bog'lash va SX zanjirlari o'zgarishsiz ishlaydi. RP-001/005/006/007/008 Kubernetes shartlari bilan. Testlar: `tests/test_kubernetes.py` |
| Compose override | `docker-compose.override.yml` / `compose.override.yaml` standart nomli fayl yonida bo'lsa, Compose kabi avtomatik birlashtiriladi; hisobotda `profile.overrides` |
| Boshqa bosqichlarda parallel skan | Kutubxona (CVE) bosqichi ham loyiha bo'yicha slotlarga o'tdi. **Image, IaC va web ataylab bittadan qoldi:** Trivy umumiy kesh bazasini qulflaydi (parallel ishga tushirish xato beradi), web esa nishonga bir vaqtda bitta so'rov qoidasiga bog'liq |
| Ikki hisobotni solishtirish | Katta hisobot yonida `compare.json` (faqat identifikator va qisqa tavsif); solishtirish shuni o'qiydi. Natija to'liq hisobotdan olingan bilan bir xil (testda tekshirilgan) |

**Kubernetes chegaralari:** fayllar yozilganidek o'qiladi. Helm shablonlari va Kustomize overlay'lari render
qilinmaydi (`{{` bo'lgan fayl "o'qilmadi" deb ko'rsatiladi), klasterga so'rov yuborilmaydi, `matchExpressions`
li NetworkPolicy himoya deb sanalmaydi, ko'p konteynerli pod'da image bog'lanishi birinchi konteyner bo'yicha.
Manba kodi bilan bog'lanish yo'q (`build_context` yo'q), shuning uchun SX-001/004/006/007 Kubernetes'da ishlamaydi —
faqat image'ga tayanadigan SX-002/003/005.

Hali ochiq qolganlar J bo'limida.

---

## J. 2026-10-13 haqiqiy vositalar bilan sinov

`setup_all.py` bilan o'rnatildi: Semgrep 1.177.0, Gitleaks 8.30.1, Trivy 0.74.0, Nuclei 3.11.1 va rasmiy
1 343 qoidali paket. PMD o'rnatilmadi (Java yo'q). Mashina: Windows 11, 12 yadro, 7,3 GB RAM.

**O'tdi:** barcha benchmarklar (oflayn: SAST 30/30, sirlar 11/11, IaC, Compose, tuzatishlar, web, ta'sir, gate;
onlayn: lockfile'lar, JVM/.NET, image — Trivy'ning o'zi bilan 85 = 85, SBOM mos), `verify_platform.py` 9/9,
1 074 unit test (ketma-ket 3 marta).

| # | Topilgan muammo | Tuzatish |
|---|---|---|
| J1 | Rasmiy paket bilan 26 503 faylni bitta yurishda skanerlash 55 daqiqada tugamadi va **hech narsa saqlamadi** | Bo'laklab skanerlash: har bo'lak natijasi darhol keshga yoziladi; bekor qilingan yoki uzilgan skan qolgan joyidan davom etadi |
| J2 | Bo'lakli skanda 4 000 faylli bo'lakka qat'iy 15 daqiqa berilgan; kattaroq bo'laklar sig'madi, ikkitasi ketma-ket tugamadi va 3 351 fayl skanerlanmadi | Vaqt chegarasi tugagan bo'laklarning haqiqiy tezligidan o'rganiladi (3 × kutilgan, ko'pi bilan 4 soat); vaqtga sig'magan bo'lak ikkiga bo'linib qayta uriniladi (4 marta) — sekin fayl faqat o'zini to'xtatadi |
| J3 | **Qayta skan keshdagi 23 152 natijani yo'qotdi:** faqat avval vaqtga sig'magan fayllar qayta urinilgan, ular yana sig'magach Semgrep `failed` deb belgilanib, keshdagi topilmalar hisobotga tushmagan (1 895 → 0) | Vosita faqat yangi ish ham, kesh ham bo'sh bo'lsagina `failed`; aks holda kesh natijalari qoladi va holat `partial`. Regressiya testi eski xulq bilan yiqilishi tekshirildi |
| J4 | Rad etilgan POST'da Windows ulanishni javob yetib bormasdan uzishi mumkin edi (testlar to'plamida tasodifiy yiqilish) | Kichik o'qilmagan tana (≤ 64 KB) javobdan oldin o'qib tashlanadi. Shundan keyin to'plam 3/3 toza (oldin 3 dan 2 tasida yiqilgan) — sababi shu ekani ehtimoliy, isbotlanmagan |
| J5 | `verify_platform.py` global Semgrep versiyasini ko'rsatardi (1.174.0, o'rnatilgani 1.177.0); skanning o'zi to'g'ri versiyada ishlagan | Tekshiruv skan bilan bir xil PATH bilan ishga tushiradi |
| J6 | SQLAlchemy ifodasi (`select(...).where(col == request.args[...])`) SQL injeksiyasi deb belgilanardi | `.where/.filter/.filter_by/.values/.bindparams` sanitizer; haqiqiy Semgrep bilan tekshirildi |
| J7 | JS `client.query({query, variables: req.body})` (GraphQL) SQL injeksiyasi deb belgilanardi | Obyekt argumenti chiqarildi |
| J8 | PHP'da WordPress/Laravel ekranlash funksiyalari sanitizer emas edi | `esc_html/esc_attr/esc_url/esc_js/wp_kses/e/json_encode/urlencode/absint`, SQL uchun `$wpdb->prepare/esc_sql/(float)` |
| J9 | Gitleaks `generic-api-key`: real daraxtda 66 tadan 35 tasi konstanta nomi, `.pyi` tur izohi yoki vaqt zonasi edi | Faqat shu qoida uchun, faqat shu uch shaklga allowlist (66 → 31). Olib tashlanganlarning hammasi ko'rib chiqildi; test real kalit shakllari o'tib ketmasligini tekshiradi. (Hujjatdagi AWS namuna kalitlarini Gitleaks o'zi allaqachon o'tkazib yuboradi — bunga qoida qo'shilmadi) |
| J10 | Dev bog'liqliklar va tuzatishi yo'q CVE'lar gate'ni to'xtatardi | `--prod-only` endi faqat development deb e'lon qilingan kutubxonalarni ham chiqaradi; yangi `--fixable-only`. Standart xulq o'zgarmagan |

**Haqiqiy o'lchovlar (rasmiy 1 343 qoidali paket bilan):**

| | Birinchi skan | O'zgarishsiz qayta skan |
|---|---|---|
| stdlib, 2 305 fayl | 447 s | **30,6 s**, natija aynan bir xil (312) |
| To'liq `Lib`, 26 503 fayl (J2 dan oldin) | 2 soat 44 daqiqa, 23 152 fayl skanerlandi, 2 034 topilma | J3 xatosi tufayli yaroqsiz — tuzatilgan versiya bilan qayta o'lchanmadi |

To'liq daraxtdagi 1 895 Semgrep topilmasining 1 598 tasi vendor (site-packages), 293 tasi ishlab chiqarish
kodi. 139 Gitleaks topilmasining 138 tasi test yoki vendor kodida — `path_class` ularni zanjirlardan,
`--prod-only` esa gate'dan chiqaradi.

**Interfeysda bekor qilish jonli skanda tekshirildi:** bosishdan "Bekor qilingan" holatigacha 7 s, ishlab
turgan Semgrep jarayonlari to'xtadi, hisobot `cancelled`, vaqtinchalik nusxa o'chirildi. Jonli progress
matni ("Manba o'qilmoqda: 979/2391 fayl…") ham ishlaydi.

### Hali ochiq

- **Birinchi skan rasmiy paket bilan sekin:** bu mashinada ~10 daqiqa / 4 000 fayl (bo'sh xotira ~1 GB,
  shuning uchun bitta ishchi). 26 500 faylli loyihaning birinchi skani bir necha soat. Kuchliroq mashinada
  ishchilar soni oshadi; o'lchanmagan.
- **J2 tuzatishi to'liq daraxtda o'lchanmadi** (yana ~3 soat). Mantiq testlarda tekshirilgan.
- **Kubernetes:** Helm/Kustomize render qilinmaydi; manba ↔ workload bog'lanishi yo'q.
- **Image, IaC va web bosqichlari bittadan** (Trivy keshi qulfi, web so'rov qoidasi).
- **Topilmalar jadvalini noldan qurish** 150 000 qatorga 18–21 s (bir marta; keyin saqlanadi).
- **Inkremental kesh** hajmi va vaqt belgisi o'zgarmagan faylni ko'rmaydi (`--full` bilan chetlab o'tiladi).
- **Sinalmagan:** CodeQL, PMD/Apex (Java kerak), Linux, macOS.

---

## Qolgan holat — 2026-09-25, 0.7.0

Ro'yxatdagi **barcha kod bandlari yopildi** (A1–A28, B1–B7, C1–C6, D1–D3). Qolgani ikkitasi,
va ikkalasi ham kod nuqsoni emas:

1. **Windows natijasining o'zi.** Tekshiruv to'liq tayyor, macOS'da 8/8 o'tadi, va Windows'ga
   xos nuqsonlar alohida auditdan o'tkazildi (A28). Ishga tushirish: `VERIFY-WINDOWS.cmd`
   yoki `ci-examples/threatchain-self-test.yml`. Natijani faqat Windows mashinasi bera oladi —
   men uni bu yerda ololmayman.
2. **Disk: 17.0 GB bo'sh.** Colima to'xtatilgan (`colima is not running`). Ogohlantirish
   chegarasi 5 GB; hozir ogohlantirish yo'q. Lab image'lari kerak bo'lmasa `colima delete`
   qo'shimcha joy bo'shatadi — bu operator qarori.

### Qamrovning ataylab qoldirilgan chegaralari

Bular "hal qilinmagan muammo" emas, balki **ongli qaror**: ularni "hal qilish" taxminga
asoslangan natija berardi.

| Chegara | Nega ataylab |
|---|---|
| `pom.xml`, `build.gradle` o'qilmaydi | Versiya diapazon yoki xossa bo'lishi mumkin; aniqlash uchun build vositasini **bajarish** kerak. Bu modul repozitoriy kodini hech qachon bajarmaydi |
| `pyproject.toml` da faqat `==` qatorlar | Diapazonni hal qilish yuqoridagi sabab bilan bir xil |
| `psycopg2-binary` (versiyasiz), `chromadb>=0.6.1` | Manbaning o'zida aniq versiya yo'q — hech bir parser uni o'ylab topa olmaydi |
| Nuclei'ning 6 ta shabloni (9000+ emas) | Har biri qo'lda ko'rib chiqilgan va faqat GET; tekshirilmagan shablonni ishlatish ruxsat doirasidan chiqishi mumkin |
| Gixy darajasidagi nginx tahlili yo'q | RP-002/003/004/009/010/011 proxy-ishonchga qaratilgan; to'liq nginx tahlili uchun Gixy'ning o'zi bor |
| Masofaviy Docker daemon, SSH host skani, agent | B6 rejasidan tashqarida; ular butunlay boshqa ishonch modeli |
| RBAC va ko'p foydalanuvchi | Lokal bir foydalanuvchili vosita; server faqat 127.0.0.1 da |
| Brauzerdan manba papkasini ro'yxatga olish | Standart holatda o'chirilgan (`--allow-registration`) — brauzerga ixtiyoriy fayl yo'lini berish serverga butun diskni o'qishga yo'l ochadi. Auditda isbotlangan |
